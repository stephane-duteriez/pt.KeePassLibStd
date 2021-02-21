using NUnit.Framework;
using System;
using System.IO;

using KeePassLib.Keys;

namespace KeePass2PCL.Test.Shared.Keys
{
    [TestFixture()]
    public class KcpKeyFileTests
    {
        const string testCreateFile = "TestCreate.xml";
        const string testKey = "8tLvEMhjpojjRMV/ztVY4Jz//E1CZQNpFlvx7/2BEBE=";

        const string expectedFileStart =
@"<?xml version=""1.0"" encoding=""utf-8""?>
<KeyFile>
	<Meta>
		<Version>1.00</Version>
	</Meta>
	<Key>
		<Data>";

        const string expectedFileEnd =
    "</Data>\r\n" +
"\t</Key>\r\n" +
"</KeyFile>";

        [Test()]
        public void TestConstruct()
        {
            var expectedKeyData = new byte[32] {
        0xf2, 0xd2, 0xef, 0x10, 0xc8, 0x63, 0xa6, 0x88,
        0xe3, 0x44, 0xc5, 0x7f, 0xce, 0xd5, 0x58, 0xE0,
        0x9C, 0xFF, 0xFC, 0x4D, 0x42, 0x65, 0x03, 0x69,
        0x16, 0x5B, 0xF1, 0xEF, 0xFD, 0x81, 0x10, 0x11
      };

            var fullPath = Path.Combine(Path.GetTempPath(), testCreateFile);
            using (var fs = new FileStream(fullPath, FileMode.Create))
            {
                using (var sw = new StreamWriter(fs))
                {
                    sw.Write(expectedFileStart);
                    sw.Write(testKey);
                    sw.Write(expectedFileEnd);
                }
            }

            try
            {
                var keyFile = new KcpKeyFile(fullPath);
                var keyData = keyFile.KeyData.ReadData();
                Assert.That(keyData, Is.EqualTo(expectedKeyData));
            }
            finally
            {
                File.Delete(fullPath);
            }
        }

        [Test()]
        public void TestCreate()
        {
            var fullPath = Path.Combine(Path.GetTempPath(), testCreateFile);
            File.Create(fullPath).Close();
            KcpKeyFile.Create(fullPath, null);
            try
            {
                var fileContents = File.ReadAllText(fullPath).Trim();
               // Assert.That(fileContents.Length, Is.EqualTo(240));
               // Assert.That(fileContents, Does.StartWith(expectedFileStart));
               // Assert.That(fileContents, Does.EndWith(expectedFileEnd));
            }
            finally
            {
                File.Delete(fullPath);
            }
        }
    }
}

