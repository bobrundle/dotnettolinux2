using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Mono.Unix;
using Xunit;

#pragma warning disable CA1416

namespace FileSupportTests
{
    public class TestFileFixture : IDisposable
    {
        public string TestDir { get; }
        public const string InvalidFilePath = " <|>";
        public const string NullFilePath = null;
        public const string EmptyFilePath = "";
        public const string UnwritableFileName = "Unwritable.txt";
        public const string UnreadableFileName = "Unreadable.txt";
        public const string WritableFileName = "Writable.txt";
        public const string HiddenFileName = "HiddenFile.txt";
        public const string ReadOnlyFileName = "ReadOnly.txt";
        public const string NonExistentFileName = "NonExistent.txt";
        public const string UnreadableFolderName = "UnreadableFolder";
        public const string UnwritableFolderName = "UnwritableFolder";
        public const string ReadableFolderName = "ReadableFolder";
        public TestFileFixture()
        {
            TestDir = CreateTestDirectory();
            Directory.SetCurrentDirectory(TestDir);
            DeleteTestFiles();
            CreateTestFiles();
        }
        public void CreateTestFiles()
        {
            CreateUnwritableFile();
            CreateUnreadableFile();
            CreateWritableFile();
            CreateHiddenFile();
            CreateReadOnlyFile();
            CreateUnreadableFolder();
            CreateUnwritableFolder();
            CreateReadableFolder();
        }
        protected string CreateTestDirectory()
        {
            string testbasedir = Path.GetTempPath();
            string testDirPath = Path.Combine(testbasedir, "FileSupportTests");
            Directory.CreateDirectory(testDirPath);
            return testDirPath;
        }
        private void CreateReadOnlyFile()
        {
            string path = ReadOnlyFileName;
            CreateFile(path);
            FileAttributes fa = File.GetAttributes(path);
            File.SetAttributes(path, fa | FileAttributes.ReadOnly);
        }
        protected void CreateFile(string path)
        {
            using (FileStream fs = File.Create(path))
            {

            }
        }
        private void ClearReadOnlyAttribute(string path)
        {
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileAttributes fa = File.GetAttributes(path);
                File.SetAttributes(path, fa & (~FileAttributes.ReadOnly));
            }
            else
            {
                FileInfo fi = new FileInfo(path);
                fi.IsReadOnly = false;
            }
        }

        private void CreateHiddenFile()
        {
            string path = HiddenFileName;
            CreateFile(path);
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileAttributes fa = File.GetAttributes(path);
                File.SetAttributes(path, fa | FileAttributes.Hidden);
            }
        }

        private void CreateWritableFile()
        {
            string path = WritableFileName;
            CreateFile(path);
        }

        private void CreateReadableFolder()
        {
            string path = ReadableFolderName;
            Directory.CreateDirectory(path);
        }

        private void CreateUnreadableFile()
        {
            string path = UnreadableFileName;
            CreateFile(path);
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileSecurity fs = new FileSecurity(path, AccessControlSections.Access);
                SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                FileSystemAccessRule r = new FileSystemAccessRule(user, FileSystemRights.Read, AccessControlType.Deny);
                fs.AddAccessRule(r);
                FileInfo fi = new FileInfo(path);
                fi.SetAccessControl(fs);
            }
            else
            {
                var fi = new UnixFileInfo(path);
                fi.FileAccessPermissions = 0;
            }
        }

        private void CreateUnwritableFile()
        {
            string path = UnwritableFileName;
            CreateFile(path);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileSecurity fs = new FileSecurity(path, AccessControlSections.Access);
                SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                FileSystemAccessRule r = new FileSystemAccessRule(user, FileSystemRights.Write, AccessControlType.Deny);
                fs.AddAccessRule(r);
                FileInfo fi = new FileInfo(path);
                fi.SetAccessControl(fs);
            }
            else
            {
                var fi = new UnixFileInfo(path);
                fi.FileAccessPermissions = FileAccessPermissions.OtherRead | FileAccessPermissions.GroupRead | FileAccessPermissions.UserRead;
            }
        }

        private void CreateUnwritableFolder()
        {
            string path = UnwritableFolderName;
            Directory.CreateDirectory(path);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileSecurity fs = new FileSecurity(path, AccessControlSections.Access);
                SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                FileSystemAccessRule r = new FileSystemAccessRule(user, FileSystemRights.Write | FileSystemRights.Modify, AccessControlType.Deny);
                fs.AddAccessRule(r);
                FileInfo fi = new FileInfo(path);
                fi.SetAccessControl(fs);
            }
            else
            {
                var fi = new UnixFileInfo(path);
                fi.FileAccessPermissions = FileAccessPermissions.OtherRead | FileAccessPermissions.GroupRead | FileAccessPermissions.UserRead;
            }
        }

        private void CreateUnreadableFolder()
        {
            string path = UnreadableFolderName;
            Directory.CreateDirectory(path);
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                FileSecurity fs = new FileSecurity(path, AccessControlSections.Access);
                SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
                FileSystemAccessRule r = new FileSystemAccessRule(user, FileSystemRights.Read, AccessControlType.Deny);
                fs.AddAccessRule(r);
                FileInfo fi = new FileInfo(path);
                fi.SetAccessControl(fs);
            }
            else
            {
                var fi = new UnixFileInfo(path);
                fi.FileAccessPermissions = 0;
            }
        }
        public void ClearDenyACEs(string path)
        {
            FileSecurity fs = new FileSecurity(path, AccessControlSections.Access);
            AuthorizationRuleCollection rules = fs.GetAccessRules(true, true, typeof(SecurityIdentifier));
            SecurityIdentifier user = WindowsIdentity.GetCurrent().User;
            AuthorizationRuleCollection newRules = new AuthorizationRuleCollection();
            FileSystemSecurity fssNew = new FileSecurity();
            foreach (FileSystemAccessRule rule in rules.OfType<FileSystemAccessRule>())
            {
                if(rule.IdentityReference == user && rule.AccessControlType == AccessControlType.Deny)
                {
                    fs.RemoveAccessRule(rule);
                    FileInfo fi = new FileInfo(path);
                    fi.SetAccessControl(fs);

                }
            }
        }
        public void DeleteTestFiles()
        {
            if(File.Exists(UnwritableFileName))File.Delete(UnwritableFileName);
            if(File.Exists(UnreadableFileName))File.Delete(UnreadableFileName);
            if(File.Exists(WritableFileName))File.Delete(WritableFileName);
            if(File.Exists(HiddenFileName))File.Delete(HiddenFileName);
            if(File.Exists(ReadOnlyFileName))
            {
                ClearReadOnlyAttribute(ReadOnlyFileName);
                File.Delete(ReadOnlyFileName);
            }
            if(Directory.Exists(UnwritableFolderName))
            {
                if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    ClearDenyACEs(UnwritableFolderName);
                }
                Directory.Delete(UnwritableFolderName);
            }
            if(Directory.Exists(ReadableFolderName))Directory.Delete(ReadableFolderName);
            if(Directory.Exists(UnreadableFolderName))Directory.Delete(UnreadableFolderName);
        }
        public bool NeedsCleanup()
        {
            var flag = Environment.GetEnvironmentVariable("NOCLEANUP");
            return flag != "1";
        }
        public void Dispose()
        {
            if(NeedsCleanup())
            {
                DeleteTestFiles();
            }
        }

    }
}
