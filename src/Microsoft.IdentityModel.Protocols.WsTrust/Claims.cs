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

using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// This class is used to represent the Request Claims collection inside RequestSecurityToken.
    /// Indicate whether the claim is optional or not. 
    /// </summary>
    public class Claims
    {
        public Claims(string dialect, IEnumerable<ClaimType> claimTypes)
        {
            Dialect = dialect;
            ClaimTypes = claimTypes;
        }

        public IEnumerable<ClaimType> ClaimTypes { get; }

        public string Dialect { get; }

        public void WriteTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext)
        {
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Claims, serializationContext.TrustConstants.Namespace);
            if (!string.IsNullOrEmpty(Dialect))
                writer.WriteAttributeString(WsTrustAttributes.Dialect, Dialect);

            foreach (var claim in ClaimTypes)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ClaimType, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Uri, claim.Uri);
                writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, claim.Value);
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public static Claims ReadFrom(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {

            // <trust:Claims Dialect="edef1723-d88b-4897-a879-2d2fc62f9148">
              // <auth:ClaimType Uri="a14bf1a3-a189-4a81-9d9a-7d3dfeb7724a" xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706">
                // <auth:Value>77a6fa04-0454-4d08-8761-2a840e281399</auth:Value>
              // </auth:ClaimType>
            // </trust:Claims>

            bool isEmptyElement = reader.IsEmptyElement;

            // <trust:Claims ....>
            var dialect = reader.GetAttribute(WsTrustAttributes.Dialect);
            reader.ReadStartElement();
            var claimTypes = new List<ClaimType>();
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(WsFedElements.ClaimType, WsFed12Constants.Instance.AuthNamespace))
                {
                    claimTypes.Add(ClaimType.ReadFrom(reader, WsFed12Constants.Instance.AuthNamespace));
                }

                reader.Skip();
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new Claims(dialect, claimTypes);
        }
    }
}
