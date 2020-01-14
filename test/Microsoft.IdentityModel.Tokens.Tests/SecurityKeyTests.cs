﻿//------------------------------------------------------------------------------
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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class SecurityKeyTests
    {

        [Fact]
        public void ComputeJwkThumbprint()
        {
            var exception = Assert.Throws<NotSupportedException>(() => new ManagedKeyVaultSecurityKey.ManagedKeyVaultSecurityKey("keyid").ComputeJwkThumbprint());
            Assert.Contains("IDX10710", exception.Message);

#if !NET_CORE
            exception = Assert.Throws<PlatformNotSupportedException>(() => new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, false).ComputeJwkThumbprint());
            Assert.Contains("IDX10695", exception.Message);
#else
            var ex = Record.Exception(() => new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP256, false).ComputeJwkThumbprint());
            Assert.Null(ex);
#endif
        }

        [Theory, MemberData(nameof(ConversionKeyTheoryData))]
        public void CompareJwkThumbprints(JsonWebKeyConverterTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CompareJwkThumbprints", theoryData);
            try
            {
                JsonWebKey convertedKey;
                if (theoryData.SecurityKey is X509SecurityKey x509SecurityKey)
                    convertedKey = JsonWebKeyConverter.ConvertFromX509SecurityKey(x509SecurityKey, true);
                else
                    convertedKey = JsonWebKeyConverter.ConvertFromSecurityKey(theoryData.SecurityKey);

                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreBytesEqual(convertedKey.ComputeJwkThumbprint(), theoryData.SecurityKey.ComputeJwkThumbprint(), context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebKeyConverterTheoryData> ConversionKeyTheoryData
        {
            get
            {
                var theoryData = new TheoryData<JsonWebKeyConverterTheoryData>();

                // need to adjust the kid to match as the keys have different id's.
                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    First = true,
                    SecurityKey = KeyingMaterial.RsaSecurityKey_2048,
                    TestId = nameof(KeyingMaterial.RsaSecurityKey_2048)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.RsaSecurityKey_2048_Public,
                    TestId = nameof(KeyingMaterial.RsaSecurityKey_2048_Public)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.DefaultSymmetricSecurityKey_64,
                    TestId = nameof(KeyingMaterial.DefaultSymmetricSecurityKey_64)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.DefaultX509Key_2048_With_KeyId,
                    TestId = nameof(KeyingMaterial.DefaultX509Key_2048_With_KeyId)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.DefaultX509Key_2048,
                    TestId = nameof(KeyingMaterial.DefaultX509Key_2048)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.DefaultX509Key_2048_Public,
                    TestId = nameof(KeyingMaterial.DefaultX509Key_2048_Public)
                });
#if NET_CORE
                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.Ecdsa256Key_Public,
                    TestId = nameof(KeyingMaterial.Ecdsa256Key_Public)
                });

                theoryData.Add(new JsonWebKeyConverterTheoryData
                {
                    SecurityKey = KeyingMaterial.Ecdsa256Key,
                    TestId = nameof(KeyingMaterial.Ecdsa256Key)
                });
#endif

                return theoryData;
            }
        }
    }
}
