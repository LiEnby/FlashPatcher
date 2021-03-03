using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

namespace FlashPatcher
{
    public partial class FlashPatcherForm : Form
    {
      
        public FlashPatcherForm()
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

            SecurityIdentifier cu = WindowsIdentity.GetCurrent().User;
            SecurityIdentifier everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);

            try
            {
                Privileges.EnablePrivilege(SecurityEntity.SE_TAKE_OWNERSHIP_NAME);
            }
            catch(Exception)
            {
                console.AppendText("Failed to get SeTakeOwnershipPrivledge\r\n");
            }

            fileS.SetOwner(cu);
            File.SetAccessControl(filepath, fileS);


            fileS.SetAccessRuleProtection(false, false);

            fileS.RemoveAccessRuleAll(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Deny));
            fileS.RemoveAccessRuleAll(new FileSystemAccessRule(cu, FileSystemRights.FullControl, AccessControlType.Deny));

            fileS.SetAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.FullControl, AccessControlType.Allow));
            fileS.SetAccessRule(new FileSystemAccessRule(cu, FileSystemRights.FullControl, AccessControlType.Allow));

            File.SetAccessControl(filepath, fileS);
            File.SetAttributes(filepath, FileAttributes.Normal);
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
                    if (file.ToLower().EndsWith(".ocx") || file.ToLower().EndsWith(".dll") || file.ToLower().EndsWith(".exe"))
                    {
                        CheckFileAndAdd(file);
                    }
                }
            }
        }

        public bool PatchExe(string filepath)
        {
            try
            {
                Process[] lockingProcesses = FileUtil.WhoIsLocking(filepath).ToArray();
                foreach(Process proc in lockingProcesses)
                {
                    DialogResult res = MessageBox.Show("Flash is currently in use by (" + proc.Id.ToString() + ")" + proc.ProcessName + "\nEnd Process?", "File in use :/", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
                    if (res == DialogResult.Yes)
                        proc.Kill(); // DIE HHAHA
                    else
                        return true;
                }
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
                return false;
            }
            catch(Exception e)
            {
                MessageBox.Show(e.Message, "ERROR", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return true;
            }
            return false;
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

            flashPath = Path.Combine(localappdata, "Microsoft", "Edge", "User Data", "PepperFlash");
            ScanFolder(flashPath);
        }
        private void FlashPwner_Load(object sender, EventArgs e)
        {
            LocateExes();
        }

        private void defuseBomb_Click(object sender, EventArgs e)
        {
            defuseBomb.Enabled = false;
            if(flashExes.Items.Count > 0)
            {
                progressBar.Maximum = flashExes.Items.Count;
                List<string> copyFlashExes = new List<string>();
                foreach (string flashExe in flashExes.Items)
                {
                    copyFlashExes.Add(flashExe);
                }
                bool errored = false;
                foreach (string flashExe in copyFlashExes)
                {
                    errored = PatchExe(flashExe);
                }
                if(!errored)
                    MessageBox.Show("Patched! Your flash should work again!!!", "SUCCESS", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("No files to patch!", "File Error", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
            defuseBomb.Enabled = true;
        }

        private void addFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Flash Executable";
            ofd.Filter = "PE Executables (*.exe, *.ocx, *.dll)|*.dll;*.exe;*.ocx|ELF Executables (*.so, *.elf, *.dylib)|*.so;*.elf;*.dylib";
            DialogResult res = ofd.ShowDialog();
            if(res == DialogResult.OK)
            {
                if (!CheckFileAndAdd(ofd.FileName))
                {
                    MessageBox.Show("File selected does not contain the killswitch timestamp, cannot patch!", "Timestamp Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

        }

        private void patchProjetor(string path)
        {
            byte[] projBytes = File.ReadAllBytes(path);
            byte[] getUrlPattern = new byte[] { 0xF4, 0xE8, 0xBE, 0xFE, 0xFF, 0xFF };
            byte[] nops = new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
            Int64 getUrlLocation = GetPositionAfterMatch(projBytes, getUrlPattern);

            if (getUrlLocation == -1)
                return;

            FileStream fs = File.OpenWrite(path);
            fs.Seek(getUrlLocation+1, SeekOrigin.Begin);
            fs.Write(nops, 0x00, nops.Length);
            fs.Close();
        }

        private void deleteFile_Click(object sender, EventArgs e)
        {
            if(flashExes.SelectedIndex >= 0)
                flashExes.Items.RemoveAt(flashExes.SelectedIndex);
        }

        private void projectorPatch_Click(object sender, EventArgs e)
        {
            MessageBox.Show("This is a patch for the standalone \"projector\" program from adobe, it stops it opening your browser whenever a game tries to call javascript with getURL()\n\nNote: the projector DOES NOT HAVE A KILLSWITCH/TIMEBOMB and this is not needed to use the Flash Projector.", "Projector", MessageBoxButtons.OK, MessageBoxIcon.Information);

            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Title = "Flash Projector";
            ofd.Filter = "PE Executables (*.exe)|*.exe;|ELF Executables (*.elf)|*.elf";
            DialogResult res = ofd.ShowDialog();
            if(res == DialogResult.OK)
            {
                patchProjetor(ofd.FileName);
                MessageBox.Show("Patched! Projector should no longer open the browser!!!", "SUCCESS", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
    }
}
