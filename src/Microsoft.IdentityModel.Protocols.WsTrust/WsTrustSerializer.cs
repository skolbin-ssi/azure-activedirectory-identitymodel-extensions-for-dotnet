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
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.WsAddressing;
using Microsoft.IdentityModel.WsPolicy;
using Microsoft.IdentityModel.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Base class for support of versions of WS-Trust request messages.
    /// </summary>
    public class WsTrustSerializer
    {
        public WsTrustSerializer() {}

        public WsTrustResponse ReadRequestSecurityTokenResponse(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityTokenResponse);
            reader.MoveToContent();
            WsSerializationContext serializationContext;
            if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
            else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
            else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
            else
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15001, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));

            reader.MoveToContent();
            reader.ReadStartElement();
            var tokenResponse = ReadRequestSecurityTokenResponse(reader, serializationContext);

            return new WsTrustResponse(tokenResponse);
        }

        public RequestSecurityTokenResponse ReadRequestSecurityTokenResponse(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            // brentsch - TODO, PERF - create a collection of strings then remove theme as found
            // that will result in fewer searches
            // perhaps use a dictionary, will need perf tests

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            bool isEmptyElement = reader.IsEmptyElement;
            reader.MoveToContent();

            var tokenResponse = new RequestSecurityTokenResponse();

            while (reader.IsStartElement())
            {
                bool processed = false;
                if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.TokenType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestSecurityToken, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedSecurityToken = ReadRequestedSecurityToken(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedAttachedReference, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedAttachedReference = ReadRequestedAttachedReference(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedUnattachedReference, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedUnattachedReference = ReadRequestedUnAttachedReference(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedProofToken = ReadRequestedProofToken(reader, serializationContext);
                }
                else if (reader.IsStartElement(WsTrustElements.Entropy, serializationContext.TrustConstants.Namespace))
                {
                    tokenResponse.RequestedProofToken = ReadEntropy(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            tokenResponse.AppliesTo = ReadAppliesTo(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else
                {
                    reader.Skip();
                }

                reader.MoveToContent();
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return tokenResponse;
        }

        public RequestedSecurityToken ReadRequestedSecurityToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            return null;
        }

        public RequestedAttachedReference ReadRequestedAttachedReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            return null;
        }

        public RequestedUnattachedReference ReadRequestedUnAttachedReference(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            return null;
        }

        public RequestedProofToken ReadRequestedProofToken(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            //<wst:RequestedProofToken>
            //    <wst:BinarySecret>5p76ToaxZXMFm4W6fmCcFXfDPd9WgJIM</wst:BinarySecret>
            //</wst:RequestedProofToken>

            reader.MoveToContent();
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestedProofToken, serializationContext.TrustConstants.Namespace);
            var isEmptyElement = reader.IsEmptyElement;

            reader.ReadStartElement();
            reader.MoveToContent();
            BinarySecret binarySecret = null;
            if (reader.IsStartElement(WsTrustElements.BinarySecret, serializationContext.TrustConstants.Namespace))
            {
                if (reader.IsEmptyElement)
                    // brentsch - TODO, error message
                    throw LogHelper.LogExceptionMessage(new WsTrustReadException("BinarySecret is empty element"));

                var type = reader.GetAttribute(WsTrustAttributes.Type, serializationContext.TrustConstants.Namespace);
                var data = reader.ReadContentAsBase64();

                if (!string.IsNullOrEmpty(type) && data != null)
                    binarySecret = new BinarySecret(data, type);
                else if (data != null)
                    binarySecret = new BinarySecret(data);
                else
                    // brentsch - TODO, error message
                    throw LogHelper.LogExceptionMessage(new WsTrustReadException("BinarySecret missing"));
            }
            else
            {
                // brentsch - TODO, test for empty element
                reader.Skip();
            }

            // brentsch - TODO, add additional scenarios for Requested proof token;
            RequestedProofToken proofToken = null;
            if (binarySecret != null)
                proofToken = new RequestedProofToken(binarySecret);
            else
                LogHelper.LogExceptionMessage(new WsTrustReadException("The only Supported scenario is: BinarySecret in Requested Proof token"));

            if (!isEmptyElement)
                reader.ReadEndElement();

            return proofToken;
        }

        public RequestedProofToken ReadEntropy(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            return null;
        }

        public Lifetime ReadLifetime(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {
            return null;
        }

        public WsTrustRequest ReadRequestSecurityToken(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsTrustElements.RequestSecurityToken);
            reader.MoveToContent();
            WsSerializationContext serializationContext;
            if (reader.IsNamespaceUri(WsTrustConstants.Trust13.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust13);
            else if (reader.IsNamespaceUri(WsTrustConstants.TrustFeb2005.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005);
            else if (reader.IsNamespaceUri(WsTrustConstants.Trust14.Namespace))
                serializationContext = new WsSerializationContext(WsTrustVersion.Trust14);
            else
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15001, WsTrustConstants.TrustFeb2005, WsTrustConstants.Trust13, WsTrustConstants.Trust14, reader.NamespaceURI)));

            var trustRequest = new WsTrustRequest
            {
                Context = reader.GetAttribute(WsTrustAttributes.Context)
            };

            reader.MoveToContent();
            reader.ReadStartElement();
            ReadRequestSecurityToken(reader, serializationContext, trustRequest);

            // brentsch TODO - need to store unknown elements.
            return trustRequest;
        }

        public WsTrustRequest ReadRequestSecurityToken(XmlDictionaryReader reader, WsSerializationContext serializationContext, WsTrustRequest trustRequest)
        {
            // brentsch - TODO, PERF - create a collection of strings then remove theme as found
            // that will result in fewer searches
            // perhaps use a dictionary, will need perf tests

            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            bool isEmptyElement = reader.IsEmptyElement;
            reader.MoveToContent();
            while (reader.IsStartElement())
            {
                bool processed = false;
                if (reader.IsStartElement(WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.RequestType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.TokenType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeyType = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.KeySizeInBits = XmlUtil.ReadIntElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.CanonicalizationAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptionAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.EncryptWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.SignWith = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsStartElement(WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.ComputedKeyAlgorithm = XmlUtil.ReadStringElement(reader);
                }
                else if (reader.IsLocalName(WsPolicyElements.AppliesTo))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AppliesTo = ReadAppliesTo(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }
                   
                    if (!processed)
                        reader.Skip();
                }
                else if (reader.IsLocalName(WsFedElements.AdditionalContext))
                {
                    foreach (var @namespace in WsFedConstants.KnownAuthNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AdditionalContext = ReadAdditionalContext(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else if (reader.IsStartElement(WsTrustElements.Claims, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.Claims = ReadClaims(reader, serializationContext);
                }
                else if (reader.IsLocalName(WsPolicyElements.PolicyReference))
                {
                    foreach (var @namespace in WsPolicyConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.PolicyReference = ReadPolicyReference(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }
                }
                else
                {
                    reader.Skip();
                }

                reader.MoveToContent();
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return trustRequest;
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual AdditionalContext ReadAdditionalContext(XmlDictionaryReader reader, string @namespace)
        {
            // brentsch - TODO, I think a static list of all namespaces for all known versions would help.
            if (XmlUtil.IsStartElement(reader, WsFedElements.AdditionalContext, WsFedConstants.KnownNamespaces))
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30011, WsFedElements.AdditionalContext, WsFedConstants.Fed12.Namespace, reader.LocalName, reader.NamespaceURI)));

            //  <auth:AdditionalContext xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706">
            //    <auth:ContextItem Name="http://referenceUri" Scope="8954b59e-3907-4939-976d-959395583ecb">
            //      <auth:Value>90b88c42-55ca-4e4c-a45f-cde102383f3b</auth:Value>
            //    </auth:ContextItem>
            //  </auth:AdditionalContext>

            var additionalContext = new AdditionalContext();
            if (reader.IsEmptyElement)
                return additionalContext;

            // brentsch - TODO, this is an open spec, we are skipping all unknown attributes.
            reader.ReadStartElement();
            reader.MoveToContent();
            try
            {
                while (reader.IsStartElement())
                {
                    // brentsch - TODO, need to account for namespace
                    if (!reader.IsEmptyElement && reader.IsStartElement(WsFedElements.ContextItem, @namespace))
                    {
                        var name = reader.GetAttribute(WsFedAttributes.Name);
                        if (string.IsNullOrEmpty(name))
                            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

                        var contextItem = new ContextItem(name);
                        contextItem.Scope = reader.GetAttribute(WsFedAttributes.Scope);
                        reader.ReadStartElement();
                        reader.MoveToContent();
                        if (!reader.IsEmptyElement && reader.IsStartElement(WsFedElements.Value, @namespace))
                        {
                            reader.ReadStartElement();
                            contextItem.Value = reader.ReadContentAsString();
                            reader.MoveToContent();
                            reader.ReadEndElement();
                        }
                        else
                        {
                            reader.Skip();
                        }

                        // </ContextItem>
                        reader.ReadEndElement();
                        additionalContext.Items.Add(contextItem);
                    }
                    else
                    {
                        reader.Skip();
                    }

                    reader.MoveToContent();
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30016, WsFedElements.ContextItem), ex));
            }

            // </AdditionalContext>
            reader.ReadEndElement();
            return additionalContext;
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <param name="namespace"></param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual AppliesTo ReadAppliesTo(XmlDictionaryReader reader, string @namespace)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.AppliesTo, @namespace);

            // brentsch - TODO, TESTCASE
            if (reader.IsEmptyElement)
            {
                reader.Skip();
                return new AppliesTo();
            }

            reader.ReadStartElement();
            var appliesTo = new AppliesTo { EndpointReference = ReadEndpointReference(reader) };
            reader.ReadEndElement();

            return appliesTo;
        }

        public virtual Claims ReadClaims(XmlDictionaryReader reader, WsSerializationContext serializationContext)
        {

            // <trust:Claims Dialect="edef1723d88b4897a8792d2fc62f9148">
              // <auth:ClaimType Uri="a14bf1a3a1894a819d9a7d3dfeb7724a" xmlns:auth="http://docs.oasisopen.org/wsfed/authorization/200706">
                // <auth:Value>77a6fa0404544d0887612a840e281399</auth:Value>
              // </auth:ClaimType>
            // </trust:Claims>

            bool isEmptyElement = reader.IsEmptyElement;

            // <trust:Claims ....>
            var dialect = reader.GetAttribute(WsTrustAttributes.Dialect);
            reader.ReadStartElement();
            var claimTypes = new List<ClaimType>();
            while (reader.IsStartElement())
            {
                if (reader.IsLocalName(WsFedElements.ClaimType))
                {
                    foreach (var @namespace in WsFed12Constants.KnownAuthNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            claimTypes.Add(ReadClaimType(reader, @namespace));
                        }
                    }
                }
                else
                {
                    reader.Skip();
                }
            }

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new Claims(dialect, claimTypes);
        }

        /// <summary>
        /// Creates and populates a <see cref="ClaimType"/> by reading xml.
        /// Expects the <see cref="XmlDictionaryReader"/> to be positioned on the StartElement: "ClaimType" in the namespace passed in.
        /// </summary>
        /// <param name="reader">a <see cref="XmlDictionaryReader"/> positioned at the StartElement: "ClaimType".</param>
        /// <param name="namespace">the namespace for the StartElement.</param>
        /// <returns>a populated <see cref="ClaimType"/>.</returns>
        /// <remarks>Checking for the correct StartElement is as follows.</remarks>
        /// <remarks>if @namespace is null, then <see cref="XmlDictionaryReader.IsLocalName(string)"/> will be called.</remarks>
        /// <remarks>if @namespace is not null or empty, then <see cref="XmlDictionaryReader.IsStartElement(XmlDictionaryString, XmlDictionaryString)"/> will be called.></remarks>
        /// <exception cref="ArgumentNullException">if reader is null.</exception>
        /// <exception cref="XmlReadException">if reader is not positioned on a StartElement.</exception>
        /// <exception cref="XmlReadException">if the StartElement does not match the expectations in remarks.</exception>
        public virtual ClaimType ReadClaimType(XmlDictionaryReader reader, string @namespace)
        {
            // example:
            // <auth:ClaimType Uri="a14bf1a3-a189-4a81-9d9a-7d3dfeb7724a" xmlns:auth="http://docs.oasis-open.org/wsfed/authorization/200706">
            //   <auth:Value>77a6fa04-0454-4d08-8761-2a840e281399</auth:Value>
            // </auth:ClaimType>

            XmlUtil.CheckReaderOnEntry(reader, WsFedElements.ClaimType, @namespace);
            reader.MoveToContent();
            var uri = reader.GetAttribute(WsFedAttributes.Uri);
            if (string.IsNullOrEmpty(uri))
                throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(Xml.LogMessages.IDX30013, WsFedElements.ContextItem, WsFedAttributes.Name)));

            var optionalAttribute = reader.GetAttribute(WsFedAttributes.Optional);
            bool? optional = null;
            if (!string.IsNullOrEmpty(optionalAttribute))
                optional = XmlConvert.ToBoolean(optionalAttribute);

            string value = null;
            bool isEmptyElement = reader.IsEmptyElement;
            reader.ReadStartElement();
            reader.MoveToContent();

            // brentsch - TODO, need loop for multiple elements
            if (reader.IsStartElement(WsFedElements.Value, @namespace))
                value = XmlUtil.ReadStringElement(reader);

            if (!isEmptyElement)
                reader.ReadEndElement();

            // brentsch - TODO, TESTCASE
            if (optional.HasValue && !string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, IsOptional = optional, Value = value };
            else if (optional.HasValue)
                return new ClaimType { Uri = uri, IsOptional = optional };
            else if (!string.IsNullOrEmpty(value))
                return new ClaimType { Uri = uri, Value = value };

            return new ClaimType { Uri = uri };
        }

        /// <summary>
        /// Reads an <see cref="EndpointReference"/>
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public virtual EndpointReference ReadEndpointReference(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsAddressingElements.EndpointReference);
            
            reader.MoveToContent();
            foreach(var @namespace in WsAddressingConstants.KnownNamespaces)
            {
                if (reader.IsNamespaceUri(@namespace))
                {
                    bool isEmptyElement = reader.IsEmptyElement;
                    reader.ReadStartElement();
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while (reader.IsStartElement())
                    {
                        bool isInnerEmptyElement = reader.IsEmptyElement;
                        var subtreeReader = reader.ReadSubtree();
                        var doc = new XmlDocument
                        {
                            PreserveWhitespace = true
                        };

                        doc.Load(subtreeReader);
                        endpointReference.AdditionalXmlElements.Add(doc.DocumentElement);
                        if (!isInnerEmptyElement)
                            reader.ReadEndElement();
                    }

                    if (!isEmptyElement)
                        reader.ReadEndElement();

                    return endpointReference;
                }
            }

            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15002, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing200408.Namespace, WsAddressingConstants.Addressing10.Namespace, reader.NamespaceURI)));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="namespace"></param>
        public virtual PolicyReference ReadPolicyReference(XmlDictionaryReader reader, string @namespace)
        {
            // brentsch - TODO, if this was private, we wouldn't need to check as much
            XmlUtil.CheckReaderOnEntry(reader, WsPolicyElements.PolicyReference, @namespace);

            bool isEmptyElement = reader.IsEmptyElement;
            var uri = reader.GetAttribute(WsPolicyAttributes.URI);
            var digest = reader.GetAttribute(WsPolicyAttributes.Digest);
            var digestAlgorithm = reader.GetAttribute(WsPolicyAttributes.DigestAlgorithm);
            reader.ReadStartElement();
            reader.MoveToContent();

            if (!isEmptyElement)
                reader.ReadEndElement();

            return new PolicyReference(uri, digest, digestAlgorithm);
        }

        /// <summary>
        /// Reads the 'RequestedSecurityToken' element.
        /// </summary>
        /// <returns>the 'SecurityToken'.</returns>
        protected virtual RequestedSecurityToken ReadRequestedSecurityToken(XmlReader xmlReader)
        {
            if (!XmlUtil.IsStartElement(xmlReader, WsTrustElements.RequestedSecurityToken, WsTrustConstants.KnownNamespaces))
                throw LogReadException("Message");

            xmlReader.ReadStartElement();
            xmlReader.MoveToContent();

            RequestedSecurityToken requestedSecurityToken = null;
            using (var ms = new MemoryStream())
            {
                using (var writer = XmlDictionaryWriter.CreateTextWriter(ms, Encoding.UTF8, false))
                {
                    writer.WriteNode(xmlReader, true);
                    writer.Flush();
                }
                ms.Seek(0, SeekOrigin.Begin);
                var tokenBytes = ms.ToArray();
                var token = Encoding.UTF8.GetString(tokenBytes);
                requestedSecurityToken = new RequestedSecurityToken { Token = token };
            }

            // </RequestedSecurityToken>
            xmlReader.ReadEndElement();

            return requestedSecurityToken;
        }

        public void WriteRequest(XmlDictionaryWriter writer, WsSerializationContext serializationContext, WsTrustRequest request)
        {
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestSecurityToken, serializationContext.TrustConstants.Namespace);

            if (!string.IsNullOrEmpty(request.Context))
                writer.WriteAttributeString(WsTrustAttributes.Context, request.Context);

            writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.RequestType, serializationContext.TrustConstants.Namespace, request.RequestType);

            if (!string.IsNullOrEmpty(request.TokenType))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.TokenType, serializationContext.TrustConstants.Namespace, request.TokenType);

            if (!string.IsNullOrEmpty(request.KeyType))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.KeyType, serializationContext.TrustConstants.Namespace, request.KeyType);

            if (request.KeySizeInBits.HasValue)
            {
                writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.KeySize, serializationContext.TrustConstants.Namespace);
                writer.WriteValue(request.KeySizeInBits.Value);
                writer.WriteEndElement();
            }

            if (!string.IsNullOrEmpty(request.CanonicalizationAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.CanonicalizationAlgorithm, serializationContext.TrustConstants.Namespace, request.CanonicalizationAlgorithm);

            if (!string.IsNullOrEmpty(request.EncryptionAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptionAlgorithm, serializationContext.TrustConstants.Namespace, request.EncryptionAlgorithm);

            if (!string.IsNullOrEmpty(request.EncryptWith))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.EncryptWith, serializationContext.TrustConstants.Namespace, request.EncryptWith);

            if (!string.IsNullOrEmpty(request.SignWith))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.SignWith, serializationContext.TrustConstants.Namespace, request.SignWith);

            if (!string.IsNullOrEmpty(request.ComputedKeyAlgorithm))
                writer.WriteElementString(serializationContext.TrustConstants.Prefix, WsTrustElements.ComputedKeyAlgorithm, serializationContext.TrustConstants.Namespace, request.ComputedKeyAlgorithm);

            if (request.AppliesTo != null)
                WriteAppliesTo(writer, serializationContext, request.AppliesTo);

            //if (request.OnBehalfOf != null)
            //    WriteOnBehalfOf(writer, serializationContext, request.OnBehalfOf);

            if (request.AdditionalContext != null)
                WriteAdditionalContext(writer, serializationContext, request.AdditionalContext);

            if (request.Claims != null)
                WriteClaims(writer, serializationContext, request.Claims);

            if (request.PolicyReference != null)
                WritePolicyReference(writer, serializationContext, request.PolicyReference);

            writer.WriteEndElement();
        }

        public void WriteOnBehalfOf(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenElement securityTokenElement)
        {
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace);
            securityTokenElement.WriteTo(writer);
            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="additionalContext"></param>
        public void WriteAdditionalContext(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AdditionalContext additionalContext)
        {
            writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.AdditionalContext, serializationContext.FedConstants.AuthNamespace);
            foreach (var contextItem in additionalContext.Items)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ContextItem, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Name, contextItem.Name);
                if (contextItem.Scope != null)
                    writer.WriteAttributeString(WsFedAttributes.Scope, contextItem.Scope);

                if (!string.IsNullOrEmpty(contextItem.Value))
                    writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, contextItem.Value);

                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public void WriteAppliesTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext, AppliesTo appliesTo)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.AppliesTo, serializationContext.PolicyConstants.Namespace);

            if (appliesTo.EndpointReference != null)
                WriteEndpointReference(writer, serializationContext, appliesTo.EndpointReference);

            writer.WriteEndElement();
        }

        public void WriteClaims(XmlDictionaryWriter writer, WsSerializationContext serializationContext, Claims claims)
        {
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.Claims, serializationContext.TrustConstants.Namespace);
            if (!string.IsNullOrEmpty(claims.Dialect))
                writer.WriteAttributeString(WsTrustAttributes.Dialect, claims.Dialect);

            foreach (var claim in claims.ClaimTypes)
            {
                writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.ClaimType, serializationContext.FedConstants.AuthNamespace);
                writer.WriteAttributeString(WsFedAttributes.Uri, claim.Uri);
                writer.WriteElementString(serializationContext.FedConstants.AuthPrefix, WsFedElements.Value, serializationContext.FedConstants.AuthNamespace, claim.Value);
                writer.WriteEndElement();
            }

            writer.WriteEndElement();
        }

        public void WriteEndpointReference(XmlWriter writer, WsSerializationContext serializationContext, EndpointReference endpointReference)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.EndpointReference, serializationContext.AddressingConstants.Namespace);
            writer.WriteStartElement(serializationContext.AddressingConstants.Prefix, WsAddressingElements.Address, serializationContext.AddressingConstants.Namespace);
            writer.WriteString(endpointReference.Uri.AbsoluteUri);
            writer.WriteEndElement();
            foreach (XmlElement element in endpointReference.AdditionalXmlElements)
                element.WriteTo(writer);

            writer.WriteEndElement();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        /// <param name="policyReference"></param>
        public void WritePolicyReference(XmlDictionaryWriter writer, WsSerializationContext serializationContext, PolicyReference policyReference)
        {
            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.PolicyReference, serializationContext.PolicyConstants.Namespace);
            if (!string.IsNullOrEmpty(policyReference.Uri))
                writer.WriteAttributeString(WsPolicyAttributes.URI, policyReference.Uri);

            if (!string.IsNullOrEmpty(policyReference.Digest))
                writer.WriteAttributeString(WsPolicyAttributes.Digest, policyReference.Digest);

            if (!string.IsNullOrEmpty(policyReference.DigestAlgorithm))
                writer.WriteAttributeString(WsPolicyAttributes.DigestAlgorithm, policyReference.DigestAlgorithm);

            writer.WriteEndElement();
        }

        //internal static List<string> WsTrustNamespaceList = new List<string>() { WsTrustFeb2005Constants.Instance.Namespace, WsTrust13Constants.Instance.Namespace, WsTrust14Constants.Instance.Namespace };
        //internal static List<string> WsTrustNamespaceNon2005List = new List<string>() { WsTrust13Constants.Instance.Namespace, WsTrust14Constants.Instance.Namespace };

        internal static Exception LogReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogReadException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args), inner));
        }

        internal static Exception LogWriteException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustWriteException(LogHelper.FormatInvariant(format, args)));
        }

        internal static Exception LogWriteException(string format, Exception inner, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustWriteException(LogHelper.FormatInvariant(format, args), inner));
        }
    }
}
