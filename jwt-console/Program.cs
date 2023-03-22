using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;

namespace jwt_console
{
    class Program
    {
        static void Main(string[] args)
        {
            string publicKey = File.ReadAllText(@"D:\HC\rsa_keys\publicKey.pem");
            string privateKey = File.ReadAllText(@"D:\HC\rsa_keys\privateKey.pem");

            var claims = new List<Claim>();
            claims.Add(new Claim("claim1", "value1"));
            claims.Add(new Claim("claim2", "value2"));
            claims.Add(new Claim("claim3", "value3"));

            var token = CreateToken(claims, privateKey);
            var payload = DecodeToken(token, publicKey);

            Console.WriteLine(token);
            Console.WriteLine(payload);
            Console.ReadLine();
        }

        public static string CreateToken(List<Claim> claims, string privateRsaKey)
        {
            RSAParameters rsaParams;
            using (var tr = new StringReader(privateRsaKey))
            {
                var pemReader = new PemReader(tr);
                var keyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                if (keyPair == null)
                {
                    throw new Exception("Could not read RSA private key");
                }
                var privateRsaParams = keyPair.Private as RsaPrivateCrtKeyParameters;
                rsaParams = DotNetUtilities.ToRSAParameters(privateRsaParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                Dictionary<string, object> payload = claims.ToDictionary(k => k.Type, v => (object)v.Value);
                return Jose.JWT.Encode(payload, rsa, Jose.JwsAlgorithm.RS256);
            }
        }

        public static string DecodeToken(string token, string publicRsaKey)
        {
            RSAParameters rsaParams;

            using (var tr = new StringReader(publicRsaKey))
            {
                var pemReader = new PemReader(tr);
                var publicKeyParams = pemReader.ReadObject() as RsaKeyParameters;
                if (publicKeyParams == null)
                {
                    throw new Exception("Could not read RSA public key");
                }
                rsaParams = DotNetUtilities.ToRSAParameters(publicKeyParams);
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(rsaParams);
                // This will throw if the signature is invalid
                return Jose.JWT.Decode(token, rsa, Jose.JwsAlgorithm.RS256);
            }
        }
    }
}
