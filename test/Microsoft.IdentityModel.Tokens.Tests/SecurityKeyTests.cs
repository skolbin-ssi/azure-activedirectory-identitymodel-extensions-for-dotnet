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

        [Theory, MemberData(nameof(CreateInternalIdsTheoryData))]
        public void CreateInternalIds(SecurityKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateInternalIds", theoryData);
            try
            {
                if (theoryData.ExpectedInternalId != theoryData.SecurityKey.InternalId)
                    context.AddDiff($"ExpectedInternalId: '{theoryData.ExpectedInternalId}'; actual InternalId: '{theoryData.SecurityKey.InternalId}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void CanComputeJwkThumbprint()
        {
            Assert.False(new CustomSecurityKey().CanComputeJwkThumbprint(), "CustomSecurityKey shouldn't be able to compute JWK thumbprint if CanComputeJwkThumbprint() is not overriden.");
        }


        public static TheoryData<SecurityKeyTheoryData> CreateInternalIdsTheoryData
        {
            get
            {
                return new TheoryData<SecurityKeyTheoryData>
                {
                    new SecurityKeyTheoryData
                    {
                        First = true,
                        SecurityKey = KeyingMaterial.RsaSecurityKey_2048,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.RsaSecurityKey_2048.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048)
                    },
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.RsaSecurityKey_2048_Public,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.RsaSecurityKey_2048_Public.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048_Public)
                    },
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.DefaultSymmetricSecurityKey_64,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.DefaultSymmetricSecurityKey_64.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.DefaultSymmetricSecurityKey_64)
                    },
                     // X509SecurityKey should have InternalId set to its x5t.
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.DefaultX509Key_2048,
                        ExpectedInternalId = KeyingMaterial.DefaultX509Key_2048.X5t,
                        TestId = nameof(KeyingMaterial.DefaultX509Key_2048)
                    },
                    // custom derived SecurityKey should have InternalId set to an empty string.
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = new CustomSecurityKey(),
                        ExpectedInternalId = string.Empty,
                        TestId = nameof(CustomSecurityKey)
                    },
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.JsonWebKeyRsa_2048_Public,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.JsonWebKeyRsa_2048_Public.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.JsonWebKeyRsa_2048_Public)
                    },
#if NET_CORE
                    // EcdsaSecurityKey should have InternalId set to its jwk thumbprint on core.
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.Ecdsa256Key_Public,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.Ecdsa256Key_Public.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.Ecdsa256Key_Public)
                    },
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.Ecdsa256Key,
                        ExpectedInternalId = Base64UrlEncoder.Encode(KeyingMaterial.Ecdsa256Key.ComputeJwkThumbprint()),
                        TestId = nameof(KeyingMaterial.Ecdsa256Key)
                    },
#else
                    // EcdsaSecurityKey should have InternalId set to an empty string on desktop.
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.Ecdsa256Key_Public,
                        ExpectedInternalId = string.Empty,
                        TestId = nameof(KeyingMaterial.Ecdsa256Key_Public) + "_emptyInternalId"
                    },
                    new SecurityKeyTheoryData
                    {
                        SecurityKey = KeyingMaterial.Ecdsa256Key,
                        ExpectedInternalId = string.Empty,
                        TestId = nameof(KeyingMaterial.Ecdsa256Key) + "_emptyInternalId"
                    },
#endif
                };
            }
        }

        public class SecurityKeyTheoryData : TheoryDataBase
        {
            public SecurityKey SecurityKey { get; set; }

            public string ExpectedInternalId { get; set; }
        }

        class CustomSecurityKey : SecurityKey
        {
            public override int KeySize => 1;
        }
    }
}
