/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2017 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Text;

#if !KeePassUAP
using System.Security.Cryptography;
#endif

using KeePassLib.Native;
using KeePassLib.Utility;
using System.IO;

namespace KeePassLib.Cryptography
{
    public static class CryptoUtil
	{
#if NETSTANDARD2_0
        //While an app specific salt is not the best practice for
        //password based encryption, it's probably safe enough as long as
        //it is truly uncommon. Also too much work to alter this answer otherwise.
        public static byte[] Salt;

        /// <summary>
        /// Encrypt the given string using AES.  The string can be decrypted using 
        /// DecryptStringAES().  The sharedSecret parameters must match.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
        public static string EncryptStringAES(string plainText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            string outStr = null;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, Salt);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        public static byte[] EncryptBytesAES(byte[] data, string sharedSecret)
        {
            if (null == data)
                throw new ArgumentNullException("plainText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            byte[] result = null;                       // Encrypted string to return
            RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, Salt);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                // Create a decryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (BinaryWriter swEncrypt = new BinaryWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(data);
                        }
                    }
                    result = msEncrypt.ToArray();
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return result;
        }

        /// <summary>
        /// Decrypt the given string.  Assumes the string was encrypted using 
        /// EncryptStringAES(), using an identical sharedSecret.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
        public static string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("cipherText");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, Salt);

                // Create the streams used for decryption.                
                byte[] bytes = Convert.FromBase64String(cipherText);
                using (MemoryStream msDecrypt = new MemoryStream(bytes))
                {
                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return plaintext;
        }

        public static readonly String SharedSecret = "SharedSecret_jhqowiefjnciwefo";

        /// <summary>
        /// Decrypt the given string.  Assumes the string was encrypted using 
        /// EncryptStringAES(), using an identical sharedSecret.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
        public static byte[] DecryptStringAES(byte[] ciphered, string sharedSecret)
        {
            if (null == ciphered)
                throw new ArgumentNullException("ciphered");
            if (string.IsNullOrEmpty(sharedSecret))
                throw new ArgumentNullException("sharedSecret");

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            // Declare the string used to hold
            // the decrypted text.
            byte[] decrypted = null;

            try
            {
                // generate the key from the shared secret and the salt
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, Salt);

                // Create the streams used for decryption.                
                using (MemoryStream msDecrypt = new MemoryStream(ciphered))
                {
                    // Create a RijndaelManaged object
                    // with the specified key and IV.
                    aesAlg = new RijndaelManaged();
                    aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                    // Get the initialization vector from the encrypted stream
                    aesAlg.IV = ReadByteArray(msDecrypt);
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt,
                        decryptor, CryptoStreamMode.Read))
                    {
                        using (BinaryReader srDecrypt = new BinaryReader(csDecrypt))

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            decrypted = srDecrypt.ReadBytes(Int32.MaxValue);
                    }
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            return decrypted;
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
#endif
        public static byte[] HashSha256(byte[] pbData)
		{
			if(pbData == null) throw new ArgumentNullException("pbData");

			return HashSha256(pbData, 0, pbData.Length);
		}

		public static byte[] HashSha256(byte[] pbData, int iOffset, int cbCount)
		{
			if(pbData == null) throw new ArgumentNullException("pbData");

#if DEBUG
			byte[] pbCopy = new byte[pbData.Length];
			Array.Copy(pbData, pbCopy, pbData.Length);
#endif

			byte[] pbHash;
			using(SHA256Managed h = new SHA256Managed())
			{
				pbHash = h.ComputeHash(pbData, iOffset, cbCount);
			}

#if DEBUG
			// Ensure the data has not been modified
			Debug.Assert(MemUtil.ArraysEqual(pbData, pbCopy));

			Debug.Assert((pbHash != null) && (pbHash.Length == 32));
			byte[] pbZero = new byte[32];
			Debug.Assert(!MemUtil.ArraysEqual(pbHash, pbZero));
#endif

			return pbHash;
		}

		/// <summary>
		/// Create a cryptographic key of length <paramref name="cbOut" />
		/// (in bytes) from <paramref name="pbIn" />.
		/// </summary>
		public static byte[] ResizeKey(byte[] pbIn, int iInOffset,
			int cbIn, int cbOut)
		{
			if(pbIn == null) throw new ArgumentNullException("pbIn");
			if(cbOut < 0) throw new ArgumentOutOfRangeException("cbOut");

			if(cbOut == 0) return MemUtil.EmptyByteArray;

			byte[] pbHash;
			if(cbOut <= 32) pbHash = HashSha256(pbIn, iInOffset, cbIn);
			else
			{
				using(SHA512Managed h = new SHA512Managed())
				{
					pbHash = h.ComputeHash(pbIn, iInOffset, cbIn);
				}
			}

			if(cbOut == pbHash.Length) return pbHash;

			byte[] pbRet = new byte[cbOut];
			if(cbOut < pbHash.Length)
				Array.Copy(pbHash, pbRet, cbOut);
			else
			{
				int iPos = 0;
				ulong r = 0;
				while(iPos < cbOut)
				{
					Debug.Assert(pbHash.Length == 64);
					using(HMACSHA256 h = new HMACSHA256(pbHash))
					{
						byte[] pbR = MemUtil.UInt64ToBytes(r);
						byte[] pbPart = h.ComputeHash(pbR);

						int cbCopy = Math.Min(cbOut - iPos, pbPart.Length);
						Debug.Assert(cbCopy > 0);

						Array.Copy(pbPart, 0, pbRet, iPos, cbCopy);
						iPos += cbCopy;
						++r;

						MemUtil.ZeroByteArray(pbPart);
					}
				}
				Debug.Assert(iPos == cbOut);
			}

#if DEBUG
			byte[] pbZero = new byte[pbHash.Length];
			Debug.Assert(!MemUtil.ArraysEqual(pbHash, pbZero));
#endif
			MemUtil.ZeroByteArray(pbHash);
			return pbRet;
		}

		private static bool? g_obAesCsp = null;
		internal static SymmetricAlgorithm CreateAes()
		{
			if(g_obAesCsp.HasValue)
				return (g_obAesCsp.Value ? CreateAesCsp() : new RijndaelManaged());

			SymmetricAlgorithm a = CreateAesCsp();
			g_obAesCsp = (a != null);
			return (a ?? new RijndaelManaged());
		}

		private static SymmetricAlgorithm CreateAesCsp()
		{
			try
			{
				// On Windows, the CSP implementation is only minimally
				// faster (and for key derivations it's not used anyway,
				// as KeePass uses a native implementation based on
				// CNG/BCrypt, which is much faster)
				if(!NativeLib.IsUnix()) return null;

				string strFqn = Assembly.CreateQualifiedName(
					"System.Core, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
					"System.Security.Cryptography.AesCryptoServiceProvider");

				Type t = Type.GetType(strFqn);
				if(t == null) return null;

				return (Activator.CreateInstance(t) as SymmetricAlgorithm);
			}
			catch(Exception) { Debug.Assert(false); }

			return null;
		}
	}
}
