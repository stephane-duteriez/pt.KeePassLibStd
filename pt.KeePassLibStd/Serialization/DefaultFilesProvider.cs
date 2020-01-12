using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KeePassLib.Serialization
{
    public sealed class DefaultFilesProvider : IFilesProvider
    {
        public Stream OpenWriteLocal(String fullname)
        {
            return new FileStream(fullname, FileMode.Create, FileAccess.Write,
                FileShare.None);
        }

        public Stream OpenReadLocal(String fullname)
        {
            return new FileStream(fullname, FileMode.Open, FileAccess.Read,
                FileShare.Read);
        }

        public Boolean IsFileExist(String fullname)
        {
            return File.Exists(fullname);
        }

        public void DeleteFile(String fullname)
        {
            File.Delete(fullname);
        }

        public void MoveFile(String from, String to)
        {
            File.Move(from, to);
        }
    }
}
