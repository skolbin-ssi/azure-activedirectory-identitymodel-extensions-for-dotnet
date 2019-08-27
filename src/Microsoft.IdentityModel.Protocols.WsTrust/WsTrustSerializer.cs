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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.WsAddressing;
using Microsoft.IdentityModel.Xml;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

#pragma warning disable 1591

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Base class for support of versions of WS-Trust request messages.
    /// </summary>
    public class WsTrustSerializer
    {
        public WsTrustSerializer() {}

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

            reader.MoveToContent();
            while (reader.IsStartElement())
            {
                bool processed = false;

                // brentsch - TODO, TESTCASE
                if (reader.IsEmptyElement)
                {
                    reader.Skip();
                    continue;
                }

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
                    foreach (var @namespace in WsFedConstants.KnownNamespaces)
                    {
                        if (reader.IsNamespaceUri(@namespace))
                        {
                            trustRequest.AdditionalContext = AdditionalContext.ReadFrom(reader, @namespace);
                            processed = true;
                            break;
                        }
                    }

                    if (!processed)
                        reader.Skip();
                }
                else if (reader.IsStartElement(WsTrustElements.Claims, serializationContext.TrustConstants.Namespace))
                {
                    trustRequest.Claims = Claims.ReadFrom(reader, serializationContext);
                }
                else
                {
                    reader.Skip();
                }

                reader.MoveToContent();
            }

            return trustRequest;
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

        /// <summary>
        /// Reads an <see cref="EndpointReference"/>
        /// </summary>
        /// <param name="reader">The xml dictionary reader.</param>
        /// <returns>An <see cref="EndpointReference"/> instance.</returns>
        public static EndpointReference ReadEndpointReference(XmlDictionaryReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, WsAddressingElements.EndpointReference);
            
            reader.ReadStartElement();
            reader.MoveToContent();

            foreach(var @namespace in WsAddressingConstants.KnownNamespaces)
            {
                if (reader.IsNamespaceUri(@namespace))
                {
                    var endpointReference = new EndpointReference(reader.ReadElementContentAsString());
                    while (reader.IsStartElement())
                    {
                        bool emptyElement = reader.IsEmptyElement;
                        XmlReader subtreeReader = reader.ReadSubtree();
                        XmlDocument doc = new XmlDocument();
                        doc.PreserveWhitespace = true;
                        doc.Load(subtreeReader);
                        endpointReference.AdditionalXmlElements.Add(doc.DocumentElement);
                        if (!emptyElement)
                            reader.ReadEndElement();
                    }

                    reader.ReadEndElement();
                    return endpointReference;
                }
            }

            throw LogHelper.LogExceptionMessage(new XmlReadException(LogHelper.FormatInvariant(LogMessages.IDX15002, WsAddressingElements.EndpointReference, WsAddressingConstants.Addressing200408.Namespace, WsAddressingConstants.Addressing10.Namespace, reader.NamespaceURI)));
        }

        public void WriteXml(XmlDictionaryWriter writer, WsSerializationContext serializationContext, WsTrustRequest request)
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
                request.AppliesTo.WriteTo(writer, serializationContext);

            //if (request.OnBehalfOf != null)
            //    WriteOnBehalfOf(writer, serializationContext, request.OnBehalfOf);

            if (request.AdditionalContext != null)
                request.AdditionalContext.WriteTo(writer, serializationContext);

            if (request.Claims != null)
                request.Claims.WriteTo(writer, serializationContext);

            if (request.PolicyReference != null)
                request.PolicyReference.WriteTo(writer, serializationContext);

            #region hidden
            /*

                        if (rst.Entropy != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Entropy, rst.Entropy, rst, context);
                        }

                        if (rst.Lifetime != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Lifetime, rst.Lifetime, rst, context);
                        }

                        if (rst.RenewTarget != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.RenewTarget, rst.RenewTarget, rst, context);
                        }

                        if (rst.ActAs != null)
                        {
                            requestSerializer.WriteXmlElement(writer, WSTrust14Constants.Elements.ActAs, rst.ActAs, rst, context);
                        }

                        if (rst.UseKey != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.UseKey, rst.UseKey, rst, context);
                        }

                        if (!string.IsNullOrEmpty(rst.AuthenticationType))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.AuthenticationType, rst.AuthenticationType, rst, context);
                        }


                        if (rst.BinaryExchange != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.BinaryExchange, rst.BinaryExchange, rst, context);
                        }

                        if (rst.Issuer != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Issuer, rst.Issuer, rst, context);
                        }

                        if (rst.ProofEncryption != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.ProofEncryption, rst.ProofEncryption, rst, context);
                        }

                        if (rst.Encryption != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Encryption, rst.Encryption, rst, context);
                        }

                        if (rst.DelegateTo != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.DelegateTo, rst.DelegateTo, rst, context);
                        }

                        if (rst.Forwardable != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Forwardable, rst.Forwardable.Value, rst, context);
                        }

                        if (rst.Delegatable != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Delegatable, rst.Delegatable.Value, rst, context);
                        }

                        if (rst.AllowPostdating)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.AllowPostdating, rst.AllowPostdating, rst, context);
                        }

                        if (rst.Renewing != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Renewing, rst.Renewing, rst, context);
                        }

                        if (rst.CancelTarget != null)
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.CancelTarget, rst.CancelTarget, rst, context);
                        }

                        if ((rst.Participants != null) && ((rst.Participants.Primary != null) || (rst.Participants.Participant.Count > 0)))
                        {
                            requestSerializer.WriteXmlElement(writer, trustConstants.Elements.Participants, rst.Participants, rst, context);
                        }
                        */
            #endregion hidden

            // Step 6: close the RST element
            writer.WriteEndElement();
        }

        public void WriteOnBehalfOf(XmlDictionaryWriter writer, WsSerializationContext serializationContext, SecurityTokenElement securityTokenElement)
        {
            writer.WriteStartElement(serializationContext.TrustConstants.Prefix, WsTrustElements.OnBehalfOf, serializationContext.TrustConstants.Namespace);
            securityTokenElement.WriteTo(writer);
            writer.WriteEndElement();
        }

        protected virtual void WriteAppliesTo(XmlDictionaryWriter writer, WsTrustRequest request, WsSerializationContext serializationContext)
        {
            writer.WriteStartElement(serializationContext.PolicyConstants.Prefix, WsPolicyElements.AppliesTo, serializationContext.PolicyConstants.Namespace);
            if (request.AppliesTo.EndpointReference != null)
                request.AppliesTo.EndpointReference.WriteTo(writer, serializationContext);

            writer.WriteEndElement();
        }

        /// <summary>
        /// Reads the 'RequestedSecurityToken' element.
        /// </summary>
        /// <returns>the 'SecurityToken'.</returns>
        protected virtual RequestedSecurityToken ReadRequestedSecurityToken(XmlReader xmlReader)
        {

            if (!XmlUtil.IsStartElement(xmlReader, WsTrustElements.RequestedSecurityToken, WsTrustNamespaceList))
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

        internal static List<string> WsTrustNamespaceList = new List<string>() { WsTrustFeb2005Constants.Instance.Namespace, WsTrust13Constants.Instance.Namespace, WsTrust14Constants.Instance.Namespace };
        internal static List<string> WsTrustNamespaceNon2005List = new List<string>() { WsTrust13Constants.Instance.Namespace, WsTrust14Constants.Instance.Namespace };

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
