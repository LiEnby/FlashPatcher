using DontTouchMyFlash.Properties;
using System;
using System.Collections.Generic;
using System.IO;
using System.Media;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

namespace DontTouchMyFlash
{
    public partial class FlashPwner : Form
    {
        public FlashPwner()
        {
            InitializeComponent();
        }
        public byte[] Timestamp = new byte[] { 0x00, 0x00, 0x40, 0x46, 0x3E, 0x6F, 0x77, 0x42 };
        public byte[] Infintiy = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x7F };
        public Int64 GetPositionAfterMatch(byte[] data, byte[] pattern)
        {
            for (Int64 i = 0; i < data.LongLength - pattern.LongLength; i++)
            {
                bool match = true;
                for (Int64 k = 0; k < pattern.LongLength; k++)
                {
                    if (data[i + k] != pattern[k])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return i;
                }
            }
            return -1;
        }

        public void TakeOwn(string filepath)
        {
            FileSecurity fileS = File.GetAccessControl(filepath);

            IdentityReference sid = fileS.GetOwner(typeof(SecurityIdentifier));
            string ntAccount = sid.Translate(typeof(NTAccount)).ToString();
            if(ntAccount == @"NT SERVICE\TrustedInstaller")
            {
                SecurityIdentifier cu = WindowsIdentity.GetCurrent().User;
                fileS.SetOwner(cu);
                fileS.SetAccessRule(new FileSystemAccessRule(cu, FileSystemRights.FullControl, AccessControlType.Allow));

                File.SetAccessControl(filepath, fileS);
            }
        }
        public bool CheckFileAndAdd(string filepath)
        {
            try
            {
                byte[] fileData = File.ReadAllBytes(filepath);
                Int64 timestampLocation = GetPositionAfterMatch(fileData, Timestamp);
                if (timestampLocation != -1)
                {
                    flashExes.Items.Add(filepath);
                    console.AppendText("Found killswitch timestamp in " + Path.GetFileName(filepath) + " @ 0x" + timestampLocation.ToString("X") + "\r\n");
                    return true;
                }
                return false;
            }
            catch(Exception)
            {
                return false;
            }
        }
        public void ScanFolder(string path)
        {
            if(Directory.Exists(path))
            {
                String[] fileList = Directory.GetFiles(path, "*", SearchOption.AllDirectories);
                foreach (string file in fileList)
                {
                    if (file.EndsWith("*.ocx") || file.EndsWith(".dll") || file.EndsWith(".exe"))
                    {
                        CheckFileAndAdd(file);
                    }
                }
            }
        }

        public void PatchExe(string filepath)
        {
            try
            {
                byte[] fileData = File.ReadAllBytes(filepath);
                Int64 timestampLocation = GetPositionAfterMatch(fileData, Timestamp);
                TakeOwn(filepath);
                FileStream fs = File.OpenWrite(filepath);
                fs.Seek(timestampLocation, SeekOrigin.Begin);
                fs.Write(Infintiy, 0x00, Infintiy.Length);
                fs.Close();
                console.AppendText("Patched: " + Path.GetFileName(filepath) + ".\r\n");
                flashExes.Items.Remove(filepath);
                Application.DoEvents();
                progressBar.Increment(1);
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }
        public void LocateExes()
        {
            string windir = Environment.GetEnvironmentVariable("WINDIR");
            string localappdata = Environment.GetEnvironmentVariable("LOCALAPPDATA");

            string flashPath = Path.Combine(windir, "System32", "Macromed", "Flash");
            ScanFolder(flashPath);

            flashPath = Path.Combine(windir, "SysWOW64", "Macromed", "Flash");
            ScanFolder(flashPath);


            flashPath = Path.Combine(localappdata, "Google", "Chrome", "User Data", "PepperFlash");
            ScanFolder(flashPath);
        }
        private void FlashPwner_Load(object sender, EventArgs e)
        {
            LocateExes();
        }

        private void defuseBomb_Click(object sender, EventArgs e)
        {
            if(flashExes.Items.Count > 0)
            {
                progressBar.Maximum = flashExes.Items.Count;
                List<string> copyFlashExes = new List<string>();
                foreach (string flashExe in flashExes.Items)
                {
                    copyFlashExes.Add(flashExe);
                }
                foreach (string flashExe in copyFlashExes)
                {
                    PatchExe(flashExe);
                }
                MessageBox.Show("Patched! Your flash should work again!!!", "SUCCESS", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("No files to patch!", "File Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }

        }

        private void addFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "PE Executable";
            ofd.Filter = "PE Executables (*.exe, *.ocx, *.dll)|*.dll;*.exe;*.ocx";
            ofd.ShowDialog();
            if (!CheckFileAndAdd(ofd.FileName))
            {
                MessageBox.Show("File selected does not contain the killswitch timestamp, cannot patch!", "Timestamp Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void deleteFile_Click(object sender, EventArgs e)
        {
            flashExes.Items.RemoveAt(flashExes.SelectedIndex);
        }
    }
}
