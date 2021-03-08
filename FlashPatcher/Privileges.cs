
using System;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

public static class Privileges
{
    public static void EnablePrivilege(SecurityEntity securityEntity)
    {
        if (!Enum.IsDefined(typeof(SecurityEntity), securityEntity))
            throw new InvalidEnumArgumentException("securityEntity", (int)securityEntity, typeof(SecurityEntity));

        var securityEntityValue = GetSecurityEntityValue(securityEntity);
        try
        {
            var locallyUniqueIdentifier = new NativeMethods.LUID();

            if (NativeMethods.LookupPrivilegeValue(null, securityEntityValue, ref locallyUniqueIdentifier))
            {
                var TOKEN_PRIVILEGES = new NativeMethods.TOKEN_PRIVILEGES();
                TOKEN_PRIVILEGES.PrivilegeCount = 1;
                TOKEN_PRIVILEGES.Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;
                TOKEN_PRIVILEGES.Luid = locallyUniqueIdentifier;

                var tokenHandle = IntPtr.Zero;
                try
                {
                    var currentProcess = NativeMethods.GetCurrentProcess();
                    if (NativeMethods.OpenProcessToken(currentProcess, NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out tokenHandle))
                    {
                        if (NativeMethods.AdjustTokenPrivileges(tokenHandle, false,
                                            ref TOKEN_PRIVILEGES,
           1024, IntPtr.Zero, IntPtr.Zero))
                        {
                            var lastError = Marshal.GetLastWin32Error();
                            if (lastError == NativeMethods.ERROR_NOT_ALL_ASSIGNED)
                            {
                                var win32Exception = new Win32Exception();
                                throw new InvalidOperationException("AdjustTokenPrivileges failed.", win32Exception);
                            }
                        }
                        else
                        {
                            var win32Exception = new Win32Exception();
                            throw new InvalidOperationException("AdjustTokenPrivileges failed.", win32Exception);
                        }
                    }
                    else
                    {
                        var win32Exception = new Win32Exception();

                        var exceptionMessage = string.Format(CultureInfo.InvariantCulture,
                                            "OpenProcessToken failed. CurrentProcess: {0}",
                                            currentProcess.ToInt32());

                        throw new InvalidOperationException(exceptionMessage, win32Exception);
                    }
                }
                finally
                {
                    if (tokenHandle != IntPtr.Zero)
                        NativeMethods.CloseHandle(tokenHandle);
                }
            }
            else
            {
                var win32Exception = new Win32Exception();

                var exceptionMessage = string.Format(CultureInfo.InvariantCulture,
                                    "LookupPrivilegeValue failed. SecurityEntityValue: {0}",
                                    securityEntityValue);

                throw new InvalidOperationException(exceptionMessage, win32Exception);
            }
        }
        catch (Exception e)
        {
            var exceptionMessage = string.Format(CultureInfo.InvariantCulture,
                             "GrandPrivilege failed. SecurityEntity: {0}",
                             securityEntityValue);

            throw new InvalidOperationException(exceptionMessage, e);
        }
    }

    /// <summary>
    /// Gets the security entity value.
    /// </summary>
    /// <param name="securityEntity">The security entity.</param>
    private static string GetSecurityEntityValue(SecurityEntity securityEntity)
    {
        switch (securityEntity)
        {
            case SecurityEntity.SE_TAKE_OWNERSHIP_NAME:
                return "SeTakeOwnershipPrivilege";

            default:
                throw new ArgumentOutOfRangeException(typeof(SecurityEntity).Name);
        }
    }
}

public enum SecurityEntity
{
    SE_TAKE_OWNERSHIP_NAME,
}

internal static class NativeMethods
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool LookupPrivilegeValue(string lpsystemname, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AdjustTokenPrivileges(IntPtr tokenhandle,
                             [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
                             [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES newstate,
                             uint bufferlength, IntPtr previousState, IntPtr returnlength);

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;

    internal const int ERROR_NOT_ALL_ASSIGNED = 1300;

    internal const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    internal const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    internal const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    internal const UInt32 TOKEN_DUPLICATE = 0x0002;
    internal const UInt32 TOKEN_IMPERSONATE = 0x0004;
    internal const UInt32 TOKEN_QUERY = 0x0008;
    internal const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    internal const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    internal const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    internal const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    internal const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    internal const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    internal const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                        TOKEN_ASSIGN_PRIMARY |
                        TOKEN_DUPLICATE |
                        TOKEN_IMPERSONATE |
                        TOKEN_QUERY |
                        TOKEN_QUERY_SOURCE |
                        TOKEN_ADJUST_PRIVILEGES |
                        TOKEN_ADJUST_GROUPS |
                        TOKEN_ADJUST_DEFAULT |
                        TOKEN_ADJUST_SESSIONID);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern IntPtr GetCurrentProcess();

    [DllImport("Advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(IntPtr processHandle,
                        uint desiredAccesss,
                        out IntPtr tokenHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern Boolean CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        internal Int32 LowPart;
        internal UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        internal Int32 PrivilegeCount;
        internal LUID Luid;
        internal Int32 Attributes;
    }
}
