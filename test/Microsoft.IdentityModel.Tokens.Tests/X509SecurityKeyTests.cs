//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class X509SecurityKeyTests
    {
        [Fact]
        public void Constructor()
        {
            var context = new CompareContext();
            var expectedException = new ExpectedException(typeExpected: typeof(ArgumentNullException), substringExpected: "certificate");
            try
            {
                new X509SecurityKey((X509Certificate2)null);
                expectedException.ProcessNoException(context);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception, context);
            }

            var certificate = KeyingMaterial.DefaultCert_2048;
            expectedException = new ExpectedException(typeExpected: typeof(ArgumentNullException), substringExpected: "keyId");
            try
            {
                new X509SecurityKey(certificate, null);
                expectedException.ProcessNoException(context);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception, context);
            }

            try
            {
                new X509SecurityKey(certificate, string.Empty);
                expectedException.ProcessNoException(context);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception, context);
            }

            expectedException = ExpectedException.NoExceptionExpected;
            try
            {
                var x509SecurityKey = new X509SecurityKey(certificate);
                IdentityComparer.AreEqual(x509SecurityKey.KeyId, certificate.Thumbprint, context);
                IdentityComparer.AreEqual(x509SecurityKey.X5t, Base64UrlEncoder.Encode(certificate.GetCertHash()), context);
                IdentityComparer.AreEqual(certificate, x509SecurityKey.Certificate, context);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception, context);
            }

            try
            {
                var x509SecurityKey = new X509SecurityKey(certificate, "KID");
                IdentityComparer.AreEqual(x509SecurityKey.KeyId, "KID", context);
                IdentityComparer.AreEqual(x509SecurityKey.X5t, Base64UrlEncoder.Encode(certificate.GetCertHash()), context);
                IdentityComparer.AreEqual(certificate, x509SecurityKey.Certificate, context);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(IsAlgorithmSupportedTheoryData))]
        public void IsSupportedAlgorithm(X509SecurityKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.IsSupportedAlgorithm", theoryData);

            try
            {
                if (theoryData.X509SecurityKey.CryptoProviderFactory.IsSupportedAlgorithm(theoryData.Algorithm, theoryData.X509SecurityKey) != theoryData.IsSupported)
                    context.AddDiff($"CryptoProviderFactory.IsSupportedAlgorithm mismatch. theoryData.Algorithm: {theoryData.Algorithm}, theoryData.X509SecurityKey: {theoryData.X509SecurityKey}, theoryData.IsSupported: {theoryData.IsSupported}.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);

        }

        public static TheoryData<X509SecurityKeyTheoryData> IsAlgorithmSupportedTheoryData
        {
            get => new TheoryData<X509SecurityKeyTheoryData>
            {
                new X509SecurityKeyTheoryData(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256, SecurityAlgorithms.RsaSha256Signature, true, SecurityAlgorithms.RsaSha256Signature),
                new X509SecurityKeyTheoryData(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256_Public, SecurityAlgorithms.RsaSha256, true, SecurityAlgorithms.RsaSha256),
                new X509SecurityKeyTheoryData(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA512, SecurityAlgorithms.Aes128Encryption, false, SecurityAlgorithms.Aes128Encryption),
                new X509SecurityKeyTheoryData(KeyingMaterial.X509SecurityKeySelfSigned1024_SHA256, SecurityAlgorithms.RsaSha384, true, SecurityAlgorithms.RsaSha384),
                new X509SecurityKeyTheoryData(
                    new X509SecurityKey(KeyingMaterial.CertSelfSigned2048_SHA256)
                    {
                        CryptoProviderFactory = new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.RsaSsaPssSha256Signature })
                    },
                    SecurityAlgorithms.RsaSsaPssSha256Signature,
                    true,
                    "CustomProvider:" + SecurityAlgorithms.RsaSsaPssSha256Signature),
            };
        }

        [Fact]
        public void CanComputeJwkThumbprint()
        {
            Assert.True(KeyingMaterial.DefaultX509Key_2048.CanComputeJwkThumbprint(), "Couldn't compute JWK thumbprint on an X509SecurityKey.");
        }

    }

    public class X509SecurityKeyTheoryData : TheoryDataBase
    {
        public X509SecurityKeyTheoryData(X509Certificate2 certificate, string algorithm, bool isSupported, string testId)
        {
            X509Certificate = certificate;
            Algorithm = algorithm;
            IsSupported = isSupported;
        }

        public X509SecurityKeyTheoryData(X509SecurityKey key, string algorithm, bool isSupported, string testId)
        {
            X509SecurityKey = key;
            Algorithm = algorithm;
            IsSupported = isSupported;
        }

        public string Algorithm { get; set; }

        string KeyId { get; set; }

        public bool IsSupported { get; set; }

        public X509Certificate X509Certificate { get; set; }

        public X509SecurityKey X509SecurityKey { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
