using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PCLStorage;
using System.IO;
using System.Linq;
using KeePassLib.Serialization;
using KeePassLib.Keys;
using KeePassLib;
using KeePassLib.Security;

namespace KeePass2PCL.Test.UWP
{
    [TestClass]
    public class PwDatabaseTests
    {
        [TestMethod]
        public void Open_With_Wrong_Password_Test()
        {
            IFolder folder = SpecialFolder.Current.Local;
            IFolder testData = folder.CreateFolderAsync("TestData",
                CreationCollisionOption.OpenIfExists).Result;
            IFile file = testData.CreateFileAsync("1.kdbx",
                CreationCollisionOption.ReplaceExisting).Result;
            var fileStream = file.OpenAsync(PCLStorage.FileAccess.ReadAndWrite).Result;
            var assembly = typeof(PwDatabaseTests).GetTypeInfo().Assembly;
            var stream = assembly.GetManifestResourceStream(
                "KeePass2PCL.Test.UWP.TestData.1.kdbx");
            using (var reader = new BinaryReader(stream))
            using (var fileWriter = new BinaryWriter(fileStream))
            {
                fileWriter.Write(reader.ReadBytes((int)stream.Length));
            }

            var ci = new IOConnectionInfo();
            ci.Path = file.Path;
            var key = new CompositeKey();
            key.AddUserKey(new KcpPassword("0"));
            var db = new PwDatabase();
            bool wasException = false;
            try
            {
                db.Open(ci, key, null);
            }
            catch (InvalidCompositeKeyException)
            {
                wasException = true;
            }
            Assert.IsTrue(wasException);
            file.DeleteAsync().Wait();
            testData.DeleteAsync().Wait();
        }

        [TestMethod]
        public void Open_With_KeyFile_Test()
        {
            IFolder folder = SpecialFolder.Current.Local;
            IFolder testData = folder.CreateFolderAsync("TestData",
                CreationCollisionOption.OpenIfExists).Result;
            IFile keyFile = testData.CreateFileAsync("1.key",
                CreationCollisionOption.ReplaceExisting).Result;
            var fileStream = keyFile.OpenAsync(PCLStorage.FileAccess.ReadAndWrite).Result;
            var assembly = typeof(PwDatabaseTests).GetTypeInfo().Assembly;
            var stream = assembly.GetManifestResourceStream(
                "KeePass2PCL.Test.UWP.TestData.1.key");
            using (var reader = new BinaryReader(stream))
            using (var fileWriter = new BinaryWriter(fileStream))
            {
                fileWriter.Write(reader.ReadBytes((int)stream.Length));
            }

            IFile file = testData.CreateFileAsync("1key.kdbx",
                CreationCollisionOption.ReplaceExisting).Result;
            fileStream = file.OpenAsync(PCLStorage.FileAccess.ReadAndWrite).Result;
            assembly = typeof(PwDatabaseTests).GetTypeInfo().Assembly;
            stream = assembly.GetManifestResourceStream(
                "KeePass2PCL.Test.UWP.TestData.1key.kdbx");
            using (var reader = new BinaryReader(stream))
            using (var fileWriter = new BinaryWriter(fileStream))
            {
                fileWriter.Write(reader.ReadBytes((int)stream.Length));
            }

            var ci = new IOConnectionInfo();
            ci.Path = file.Path;
            var key = new CompositeKey();
            key.AddUserKey(new KcpKeyFile(keyFile.Path));
            var db = new PwDatabase();
            db.Open(ci, key, null);
            keyFile.DeleteAsync().Wait();
            file.DeleteAsync().Wait();
            testData.DeleteAsync().Wait();
        }

        private PwDatabase CreateTestDatabase(
            out IOConnectionInfo ci,
            out CompositeKey key,
            out IFile file)
        {
            IFolder folder = SpecialFolder.Current.Local;
            IFolder testData = folder.CreateFolderAsync("TestData",
                CreationCollisionOption.OpenIfExists).Result;
            file = testData.CreateFileAsync("1.kdbx",
                CreationCollisionOption.ReplaceExisting).Result;

            ci = new IOConnectionInfo();
            ci.Path = file.Path;
            key = new CompositeKey();
            key.AddUserKey(new KcpPassword("0"));
            var db = new PwDatabase();
            db.New(ci, key);
            return db;
        }

        [TestMethod]
        public void New_Test()
        {
            var db = CreateTestDatabase(out IOConnectionInfo ci,
                out CompositeKey key, out IFile file);
            var initialEnitiesCount = db.RootGroup.GetEntriesCount(true);
            Assert.AreNotEqual(0, initialEnitiesCount);
            db.Save(null);
            db.Close();

            Assert.IsNull(db.RootGroup);
            db = new PwDatabase();
            db.Open(ci, key, null);
            Assert.AreEqual(initialEnitiesCount,
                db.RootGroup.GetEntriesCount(true));
            db.Close();
            file.DeleteAsync().Wait();
        }

        [TestMethod]
        public void History_Test()
        {
            var db = CreateTestDatabase(out IOConnectionInfo ci, 
                out CompositeKey key, out IFile file);

            var pwEntry = new PwEntry(true, true);
            var firstTitle = "Hello";
            pwEntry.Strings.Set(PwDefs.TitleField,
                new ProtectedString(false, firstTitle));
            db.RootGroup.AddEntry(pwEntry, true);
            db.Save(null);

            pwEntry = db.RootGroup.Entries.GetAt(0);

            var secondTitle = "Peace";
            pwEntry.Strings.Set(PwDefs.TitleField,
                new ProtectedString(false, secondTitle));
            Assert.AreEqual(secondTitle, pwEntry.Strings.Get(
                PwDefs.TitleField).ReadString());
            Assert.AreEqual(0U, pwEntry.History.UCount);
         
            db.Close();
            file.DeleteAsync().Wait();
        }
    }
}
