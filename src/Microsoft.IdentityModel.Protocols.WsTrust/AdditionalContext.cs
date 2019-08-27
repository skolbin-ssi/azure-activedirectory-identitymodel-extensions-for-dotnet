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
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Protocols.WsFed
{
    /// <summary>
    /// Defines the auth:AdditionalContext element.
    /// </summary>
    public class AdditionalContext
    {
        /// <summary>
        /// 
        /// </summary>
        public AdditionalContext()
        {
            Items = new List<ContextItem>();
        }

        /// <summary>
        /// Initializes an instance of <see cref="AdditionalContext"/>
        /// </summary>
        /// <param name="items">Collection of <see cref="ContextItem"/>.</param>
        /// <exception cref="ArgumentNullException"> <paramref name="items"/> is null.</exception>
        public AdditionalContext(IList<ContextItem> items)
        {
            Items = items ?? throw LogHelper.LogArgumentNullException(nameof(items));
        }

        /// <summary>
        /// Gets the Collection of items.
        /// </summary>
        public IList<ContextItem> Items
        {
            get; set;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        /// <param name="serializationContext"></param>
        public void WriteTo(XmlDictionaryWriter writer, WsSerializationContext serializationContext)
        {
            writer.WriteStartElement(serializationContext.FedConstants.AuthPrefix, WsFedElements.AdditionalContext, serializationContext.FedConstants.AuthNamespace);
            foreach (var contextItem in Items)
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

        /// <summary>
        /// 
        /// </summary>
        public static AdditionalContext ReadFrom(XmlDictionaryReader reader, string @namespace)
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
    }
}
