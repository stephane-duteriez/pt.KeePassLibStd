using NUnit.Framework;
using System;
using KeePassLib.Utility;

#if !KeePassLib
#endif

namespace KeePass2PCL.Test.Shared.Utility
{
    [TestFixture ()]
    public class GfxUtilTests
    {
        // 16x16 all white PNG file, base64 encoded
        const string testImageData =
            "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAACXBIWXMAAAsTAAA" +
            "LEwEAmpwYAAAAB3RJTUUH3wMOFgIgmTCUMQAAABl0RVh0Q29tbWVudABDcmVhdG" +
            "VkIHdpdGggR0lNUFeBDhcAAAAaSURBVCjPY/z//z8DKYCJgUQwqmFUw9DRAABVb" +
            "QMdny4VogAAAABJRU5ErkJggg==";

        [Test]
        [Ignore("DllNotFoundException")]
        public void TestLoadImage ()
        {
            var testData = Convert.FromBase64String (testImageData);
            var image = GfxUtil.LoadImage (testData);
            Assert.That (image.Width, Is.EqualTo (16));
            Assert.That (image.Height, Is.EqualTo (16));
        }
    }
}
