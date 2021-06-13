using System;
using System.Security.AccessControl;
using Xunit;
using FileSupport;
using Xunit.Abstractions;
using System.Runtime.InteropServices;
using Mono.Unix;

#pragma warning disable CA1416

namespace FileSupportTests
{
    public class FileSupportTests : IClassFixture<TestFileFixture>
    {
        private TestFileFixture _fixture;
        public FileSupportTests(TestFileFixture fixture)
        {
            _fixture = fixture;
        }
        [Fact]
        public void IsWritableTest()
        {
            Assert.False(FileAccess.IsFileWritable(TestFileFixture.UnwritableFileName));
            Assert.Throws<UnauthorizedAccessException>(() => { System.IO.File.WriteAllText(TestFileFixture.UnwritableFileName,""); });
            Assert.True(FileAccess.IsFileWritable(TestFileFixture.WritableFileName));
            Assert.True(FileAccess.IsFileWritable(TestFileFixture.NonExistentFileName));
            Assert.True(FileAccess.IsFileWritable(TestFileFixture.InvalidFilePath));
            Assert.False(FileAccess.IsFileWritable(TestFileFixture.NullFilePath));
            Assert.False(FileAccess.IsFileWritable(TestFileFixture.EmptyFilePath));
        }

        [Fact]
        public void IsFolderReadableTest()
        {
            Assert.False(FileAccess.IsFolderReadable(TestFileFixture.UnreadableFolderName));
            Assert.ThrowsAny<UnauthorizedAccessException>(() => { System.IO.Directory.GetFiles(TestFileFixture.UnreadableFolderName); });
            Assert.True(FileAccess.IsFolderReadable(TestFileFixture.ReadableFolderName));
            Assert.False(FileAccess.IsFolderReadable(TestFileFixture.InvalidFilePath));
        }
        [Fact]
        public void IsFolderWritableTest()
        {
            Assert.False(FileAccess.IsFolderWritable(TestFileFixture.UnwritableFolderName));
            Assert.Throws<UnauthorizedAccessException>(() => { System.IO.File.WriteAllText(System.IO.Path.Combine(TestFileFixture.UnwritableFolderName,"1.tmp"),""); });
            Assert.False(FileAccess.IsFolderWritable(TestFileFixture.UnreadableFolderName));
            Assert.True(FileAccess.IsFolderWritable(TestFileFixture.ReadableFolderName));
            Assert.False(FileAccess.IsFolderWritable(TestFileFixture.InvalidFilePath));
        }

        [Fact]
        public void IsNormalFileTest()
        {
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Assert.False(FileAccess.IsNormalFile(TestFileFixture.HiddenFileName));
            else
                Assert.False(FileAccess.IsNormalFile("/dev/null"));
            Assert.False(FileAccess.IsNormalFile(_fixture.TestDir));
            Assert.True(FileAccess.IsNormalFile(TestFileFixture.WritableFileName));
        }
        [Fact]
        public void IsReadableTest()
        {
            Assert.True(FileAccess.IsFileReadable(TestFileFixture.UnwritableFileName));
            Assert.True(FileAccess.IsFileReadable(TestFileFixture.WritableFileName));
            Assert.False(FileAccess.IsFileReadable(TestFileFixture.UnreadableFileName));
            Assert.Throws<UnauthorizedAccessException>(() => { System.IO.File.ReadAllText(TestFileFixture.UnreadableFileName); });
            Assert.False(FileAccess.IsFileReadable(TestFileFixture.InvalidFilePath));
        }
        [Fact]
        public void HasFilePermissionTest()
        {
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                Assert.True(FileAccess.HasFilePermission(TestFileFixture.WritableFileName, FileSystemRights.Write));
                Assert.False(FileAccess.HasFilePermission(TestFileFixture.UnwritableFileName, FileSystemRights.Write));
            }
            else
            {
                Assert.True(FileAccess.HasFilePermission(TestFileFixture.WritableFileName, FileAccessPermissions.UserWrite
                        | FileAccessPermissions.GroupWrite
                        | FileAccessPermissions.OtherWrite));   
                Assert.False(FileAccess.HasFilePermission(TestFileFixture.UnwritableFileName, FileAccessPermissions.UserWrite
                        | FileAccessPermissions.GroupWrite
                        | FileAccessPermissions.OtherWrite));
            }
        }

        [Fact]
        public void IsReadOnlyTest()
        {
            Assert.False(FileAccess.IsReadOnly(TestFileFixture.WritableFileName));
            Assert.True(FileAccess.IsReadOnly(TestFileFixture.ReadOnlyFileName));
        }

    }
}