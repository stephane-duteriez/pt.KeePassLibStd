using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KeePassLib.Serialization
{
    public interface IFilesProvider
    {
        Stream OpenWriteLocal(String fullname);
        Stream OpenReadLocal(String fullname);
        Boolean IsFileExist(String fullname);
        void DeleteFile(String fullname);
        void MoveFile(String from, String to);
    }
}
