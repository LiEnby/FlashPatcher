
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
            case SecurityEntity.SE_ASSIGNPRIMARYTOKEN_NAME:
                return "SeAssignPrimaryTokenPrivilege";
            case SecurityEntity.SE_AUDIT_NAME:
                return "SeAuditPrivilege";
            case SecurityEntity.SE_BACKUP_NAME:
                return "SeBackupPrivilege";
            case SecurityEntity.SE_CHANGE_NOTIFY_NAME:
                return "SeChangeNotifyPrivilege";
            case SecurityEntity.SE_CREATE_GLOBAL_NAME:
                return "SeCreateGlobalPrivilege";
            case SecurityEntity.SE_CREATE_PAGEFILE_NAME:
                return "SeCreatePagefilePrivilege";
            case SecurityEntity.SE_CREATE_PERMANENT_NAME:
                return "SeCreatePermanentPrivilege";
            case SecurityEntity.SE_CREATE_SYMBOLIC_LINK_NAME:
                return "SeCreateSymbolicLinkPrivilege";
            case SecurityEntity.SE_CREATE_TOKEN_NAME:
                return "SeCreateTokenPrivilege";
            case SecurityEntity.SE_DEBUG_NAME:
                return "SeDebugPrivilege";
            case SecurityEntity.SE_ENABLE_DELEGATION_NAME:
                return "SeEnableDelegationPrivilege";
            case SecurityEntity.SE_IMPERSONATE_NAME:
                return "SeImpersonatePrivilege";
            case SecurityEntity.SE_INC_BASE_PRIORITY_NAME:
                return "SeIncreaseBasePriorityPrivilege";
            case SecurityEntity.SE_INCREASE_QUOTA_NAME:
                return "SeIncreaseQuotaPrivilege";
            case SecurityEntity.SE_INC_WORKING_SET_NAME:
                return "SeIncreaseWorkingSetPrivilege";
            case SecurityEntity.SE_LOAD_DRIVER_NAME:
                return "SeLoadDriverPrivilege";
            case SecurityEntity.SE_LOCK_MEMORY_NAME:
                return "SeLockMemoryPrivilege";
            case SecurityEntity.SE_MACHINE_ACCOUNT_NAME:
                return "SeMachineAccountPrivilege";
            case SecurityEntity.SE_MANAGE_VOLUME_NAME:
                return "SeManageVolumePrivilege";
            case SecurityEntity.SE_PROF_SINGLE_PROCESS_NAME:
                return "SeProfileSingleProcessPrivilege";
            case SecurityEntity.SE_RELABEL_NAME:
                return "SeRelabelPrivilege";
            case SecurityEntity.SE_REMOTE_SHUTDOWN_NAME:
                return "SeRemoteShutdownPrivilege";
            case SecurityEntity.SE_RESTORE_NAME:
                return "SeRestorePrivilege";
            case SecurityEntity.SE_SECURITY_NAME:
                return "SeSecurityPrivilege";
            case SecurityEntity.SE_SHUTDOWN_NAME:
                return "SeShutdownPrivilege";
            case SecurityEntity.SE_SYNC_AGENT_NAME:
                return "SeSyncAgentPrivilege";
            case SecurityEntity.SE_SYSTEM_ENVIRONMENT_NAME:
                return "SeSystemEnvironmentPrivilege";
            case SecurityEntity.SE_SYSTEM_PROFILE_NAME:
                return "SeSystemProfilePrivilege";
            case SecurityEntity.SE_SYSTEMTIME_NAME:
                return "SeSystemtimePrivilege";
            case SecurityEntity.SE_TAKE_OWNERSHIP_NAME:
                return "SeTakeOwnershipPrivilege";
            case SecurityEntity.SE_TCB_NAME:
                return "SeTcbPrivilege";
            case SecurityEntity.SE_TIME_ZONE_NAME:
                return "SeTimeZonePrivilege";
            case SecurityEntity.SE_TRUSTED_CREDMAN_ACCESS_NAME:
                return "SeTrustedCredManAccessPrivilege";
            case SecurityEntity.SE_UNDOCK_NAME:
                return "SeUndockPrivilege";
            default:
                throw new ArgumentOutOfRangeException(typeof(SecurityEntity).Name);
        }
    }
}

public enum SecurityEntity
{
    SE_CREATE_TOKEN_NAME,
    SE_ASSIGNPRIMARYTOKEN_NAME,
    SE_LOCK_MEMORY_NAME,
    SE_INCREASE_QUOTA_NAME,
    SE_UNSOLICITED_INPUT_NAME,
    SE_MACHINE_ACCOUNT_NAME,
    SE_TCB_NAME,
    SE_SECURITY_NAME,
    SE_TAKE_OWNERSHIP_NAME,
    SE_LOAD_DRIVER_NAME,
    SE_SYSTEM_PROFILE_NAME,
    SE_SYSTEMTIME_NAME,
    SE_PROF_SINGLE_PROCESS_NAME,
    SE_INC_BASE_PRIORITY_NAME,
    SE_CREATE_PAGEFILE_NAME,
    SE_CREATE_PERMANENT_NAME,
    SE_BACKUP_NAME,
    SE_RESTORE_NAME,
    SE_SHUTDOWN_NAME,
    SE_DEBUG_NAME,
    SE_AUDIT_NAME,
    SE_SYSTEM_ENVIRONMENT_NAME,
    SE_CHANGE_NOTIFY_NAME,
    SE_REMOTE_SHUTDOWN_NAME,
    SE_UNDOCK_NAME,
    SE_SYNC_AGENT_NAME,
    SE_ENABLE_DELEGATION_NAME,
    SE_MANAGE_VOLUME_NAME,
    SE_IMPERSONATE_NAME,
    SE_CREATE_GLOBAL_NAME,
    SE_CREATE_SYMBOLIC_LINK_NAME,
    SE_INC_WORKING_SET_NAME,
    SE_RELABEL_NAME,
    SE_TIME_ZONE_NAME,
    SE_TRUSTED_CREDMAN_ACCESS_NAME
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
