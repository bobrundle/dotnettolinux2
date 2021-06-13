using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Mono.Unix;

#pragma warning disable CA1416

namespace FileSupport
{
    public static class FileAccess
    {
        /// <summary>
        /// Determines whether the the file indicated by the path is readable.  To be readable means that the file can be opened to an input stream and bytes can be
        /// read from the stream.
        /// </summary>
        /// <param name="path">The relative or absolute path to the file to be tested.</param>
        /// <returns>True, if the file is readable.</returns>
        public static bool IsFileReadable(string path)
        {
            if (File.Exists(path))
            {
                if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return  IsNormalFile(path) && HasFilePermission(path, FileSystemRights.Read);
                }
                else
                {
                    return IsNormalFile(path) && HasFilePermission(path, FileAccessPermissions.UserRead | FileAccessPermissions.GroupRead | FileAccessPermissions.OtherRead);
                }
            }
            return false;
        }
        /// <summary>
        /// Determines whether the the folder indicated by the path is readable.  To be readable means that the folder contents can be
        /// listed.
        /// </summary>
        /// <param name="path">The relative or absolute path to the folder to be tested.</param>
        /// <returns>True, if the folder is readable.</returns>
        public static bool IsFolderReadable(string path)
        {
            if (Directory.Exists(path)) 
            {
                if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return HasFilePermission(path, FileSystemRights.Read);
                }
                else
                {
                    return HasFilePermission(path, FileAccessPermissions.UserRead | FileAccessPermissions.GroupRead | FileAccessPermissions.OtherRead);
                }
            }
            return false;
        }
        /// <summary>
        /// This method determines whether the file indicated by the path argument is writable. To be writable in this context
        /// means that the file can be either modified, appended to, overwritten or deleted.  If the file does not exist, it can
        /// be created.
        /// </summary>
        /// <param name="path">The path to the file to test for writability.  The path may be either relative or absolute.</param>
        /// <returns>True, if the file is writable.</returns>
        public static bool IsFileWritable(string path)
        {
            bool result = false;
            if (File.Exists(path))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    result = IsNormalFile(path) && !IsReadOnly(path) && HasFilePermission(path, FileSystemRights.Modify);
                else
                    result = IsNormalFile(path) && HasFilePermission(path, FileAccessPermissions.UserWrite | FileAccessPermissions.UserRead 
                        | FileAccessPermissions.GroupWrite | FileAccessPermissions.GroupRead
                        | FileAccessPermissions.OtherWrite | FileAccessPermissions.OtherRead);
            }
            else
            {
                result = true;
            }
            return result && IsFolderWritable(Path.GetDirectoryName(path));
        }
        /// <summary>
        /// This method determines whether the folder indicated by the path argument is writable. To be writable in this context
        /// means that files or folders can be added or removed from the folde.
        /// </summary>
        /// <param name="path">The path to the folder to test for writability.  The path may be either relative or absolute.</param>
        /// <returns>True, if the folder is writable.</returns>
        public static bool IsFolderWritable(string path)
        {
            if (path == "") path = ".";
            if (Directory.Exists(path))
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return HasFilePermission(path, FileSystemRights.Modify);
                }
                else
                {
                    return HasFilePermission(path, FileAccessPermissions.UserWrite | FileAccessPermissions.GroupWrite | FileAccessPermissions.OtherWrite);
                }
            }
            return false;
        }
        /// <summary>
        /// Determines whether the file indicated by the path argument is a normal file.  To be a normal file in this context
        /// means that the file is not a directory and is also not encrypted, hidden, temporary or a system file.
        /// </summary>
        /// <param name="path">the path to the file to be tested.</param>
        /// <returns>True, if the indicated file is a normal file.</returns>
        public static bool IsNormalFile(string path)
        {
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileAttributes fa = File.GetAttributes(path);
                FileAttributes specialFile = FileAttributes.Directory | FileAttributes.Encrypted | FileAttributes.Hidden | FileAttributes.System | FileAttributes.Temporary;
                return (fa & specialFile) == 0;
            }
            else
            {
                var fi = new UnixFileInfo(path);
                return fi.FileType == FileTypes.RegularFile;
            }
        }
        /// <summary>
        /// Determines if the read-only file attribute is set.
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <returns>True, if the file has the read only attribute set.</returns>
        public static bool IsReadOnly(string path)
        {
            FileAttributes fa = File.GetAttributes(path);
            return (fa & FileAttributes.ReadOnly) != 0;
        }
        /// <summary>
        /// Determines whether a file has the indicated file system right.
        /// </summary>
        /// <param name="path">The path to the file</param>
        /// <param name="right">The file system right.</param>
        /// <returns>True, if the file has the indicated right.</returns>
        [SupportedOSPlatform("windows")]
        public static bool HasFilePermission(string path, FileSystemRights right)
        {
            FileSecurity fs = new FileSecurity(path,AccessControlSections.Access);
            return HasPermission(fs, right);
        }
        /// <summary>   Determines whether a file has the indicated file system right. </summary>
        ///
        /// <param name="path"> The path to the file. </param>
        /// <param name="fap">  The file access permissions to test. </param>
        ///
        /// <returns>   True, if the file has the indicated file access permissions. </returns>
        public static bool HasFilePermission(string path, FileAccessPermissions fap)
        {
            var fi = new UnixFileInfo(path);
            return HasPermission(fi, fap);
        }
        /// <summary>
        /// Determines whether the indicated file system security object has the indicated file system right.
        /// </summary>
        /// <param name="fss">The file system security object.</param>
        /// <param name="right">The file system right.</param>
        /// <returns>True, if the indicated file system security object has the indicated file system right.</returns>
        /// <remarks>The current Windows user identity is used to search the security object's ACL for 
        /// relevent allow or deny rules.  To have permission for the indicated right, the object's ACL
        /// list must contain an explicit allow rule and no deny rules for either the user identity or a group to which
        /// the user belongs.</remarks>
        [SupportedOSPlatform("windows")]
        private static bool HasPermission(FileSystemSecurity fss, FileSystemRights right)
        {
            AuthorizationRuleCollection rules = fss.GetAccessRules(true, true, typeof(SecurityIdentifier));
            var groups = WindowsIdentity.GetCurrent().Groups;
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            FileSystemRights remaining = right;
            foreach (FileSystemAccessRule rule in rules.OfType<FileSystemAccessRule>())
            {
                FileSystemRights test = rule.FileSystemRights & right;
                if (test != 0)
                {
                    if (rule.IdentityReference == user || (groups != null && groups.Contains(rule.IdentityReference)))
                    {
                        if (rule.AccessControlType == AccessControlType.Allow)
                        {
                            remaining &= ~test;
                            if (remaining == 0)return true;
                        }
                        else if (rule.AccessControlType == AccessControlType.Deny)
                        {
                            return false;
                        }
                    }
                }
            }
            return false;
        }
        /// <summary>
        /// Determines whether the indicated Unix file has the indicated file access for the current user.
        /// </summary>
        ///
        /// <remarks>
        /// The current Windows user identity is used to search the security object's ACL for relevent
        /// allow or deny rules.  To have permission for the indicated right, the object's ACL list must
        /// contain an explicit allow rule and no deny rules for either the user identity or a group to
        /// which the user belongs.
        /// </remarks>
        ///
        /// <param name="fi">   File access permissions and owner id for the Unix file.</param>
        /// <param name="fap">  The file access permissions to test. </param>
        ///
        /// <returns>
        /// True, if the indicated file system security object has the indicated file system access.
        /// </returns>
        [UnsupportedOSPlatform("windows")]
        public static bool HasPermission(UnixFileSystemInfo fi, FileAccessPermissions fap)
        {

            var effective = fi.FileAccessPermissions & fap;
            var user = UnixUserInfo.GetRealUser();
            if(user.UserId == fi.OwnerUserId)
            {
                return (effective & FileAccessPermissions.UserReadWriteExecute) == (fap & FileAccessPermissions.UserReadWriteExecute);
            }
            else if(user.GroupId == fi.OwnerGroupId)
            {
                return (effective & FileAccessPermissions.GroupReadWriteExecute) == (fap & FileAccessPermissions.GroupReadWriteExecute);
            }
            else
            {
                return (effective & FileAccessPermissions.OtherReadWriteExecute) == (fap & FileAccessPermissions.OtherReadWriteExecute);
            }
        }
    }
}
