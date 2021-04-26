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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IO;
using Xunit;

namespace Microsoft.IdentityModel.Logging.Tests
{
    public class LoggerTests
    {
        [Fact]
        public void LogMessageAndThrowException()
        {
            SampleListener listener = new SampleListener();
            // since null parameters exceptions are logged at Verbose level
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Verbose;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);
            var guid = Guid.NewGuid().ToString();
            try
            {
                throw LogHelper.LogArgumentNullException(guid);
            }
            catch (Exception ex)
            {
                Assert.Equal(typeof(ArgumentNullException), ex.GetType());
                Assert.Contains(guid, listener.TraceBuffer);
            }
        }

        [Fact]
        public void LogException()
        {
            var messageWithParams = Guid.NewGuid().ToString() + "{0}";
            var guid1 = Guid.NewGuid().ToString();
            var guid2 = Guid.NewGuid().ToString();
            var guid3 = Guid.NewGuid().ToString();
            var guid4 = Guid.NewGuid().ToString();
            var guid5 = Guid.NewGuid().ToString();

            SampleListener listener = new SampleListener();
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Critical;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Critical);

            // default logs at Error
            var exception = LogHelper.LogExceptionMessage(new ArgumentException(guid1));
            Assert.Equal(typeof(ArgumentException), exception.GetType());
            Assert.True(string.IsNullOrEmpty(listener.TraceBuffer));
            Assert.Contains(guid1, exception.Message);

            listener = new SampleListener();
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

            exception = LogHelper.LogExceptionMessage(new ArgumentException(guid1));
            Assert.Equal(typeof(ArgumentException), exception.GetType());
            Assert.Contains(guid1, exception.Message);

            exception = LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, messageWithParams, guid2)));
            Assert.Contains(guid2, exception.Message);
            Assert.Equal(typeof(ArgumentException), exception.GetType());

            exception = LogHelper.LogExceptionMessage(EventLevel.Error, new ArgumentException(String.Format(CultureInfo.InvariantCulture, messageWithParams, guid3)));
            Assert.Contains(guid3, exception.Message);

            exception = LogHelper.LogExceptionMessage(EventLevel.Error, new ArgumentException(String.Format(CultureInfo.InvariantCulture, messageWithParams, guid4), new NotSupportedException()));
            Assert.Contains(guid4, exception.Message);
            Assert.NotNull(exception.InnerException);
            Assert.Equal(typeof(NotSupportedException), exception.InnerException.GetType());

            exception = LogHelper.LogExceptionMessage(EventLevel.Informational, new ArgumentException(String.Format(CultureInfo.InvariantCulture, messageWithParams, guid5), new NotSupportedException()));
            Assert.Contains(guid5, exception.Message);
            Assert.NotNull(exception.InnerException);
            Assert.Equal(typeof(NotSupportedException), exception.InnerException.GetType());

            Assert.Contains(guid1, listener.TraceBuffer);
            Assert.Contains(guid2, listener.TraceBuffer);
            Assert.Contains(guid3, listener.TraceBuffer);
            Assert.Contains(guid4, listener.TraceBuffer);
            Assert.DoesNotContain(guid5, listener.TraceBuffer);
        }

        [Fact]
        public void TestLogLevel()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Informational;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Verbose);

            var guid1 = Guid.NewGuid().ToString();
            var guid2 = Guid.NewGuid().ToString();
            LogHelper.LogVerbose(guid1);
            LogHelper.LogInformation(guid2);

            Assert.DoesNotContain(guid1, listener.TraceBuffer);
            Assert.Contains(guid2, listener.TraceBuffer);
        }

        [Fact]
        public void FormatInvariant()
        {
            Assert.Equal(string.Empty, LogHelper.FormatInvariant(null, null));
            Assert.Equal("Formated string", LogHelper.FormatInvariant("Formated string", null));
        }

        [Fact]
        public void TextWriterEventListenerLogging()
        {
            var filename = Guid.NewGuid().ToString() + ".txt";
            var guid1 = Guid.NewGuid().ToString();
            var guid2 = Guid.NewGuid().ToString();
            var guid3 = Guid.NewGuid().ToString();

            IdentityModelEventSource.Logger.LogLevel = EventLevel.Verbose;
            using (TextWriterEventListener listener = new TextWriterEventListener(filename))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteInformation(guid1);
                IdentityModelEventSource.Logger.WriteVerbose(guid2);
                IdentityModelEventSource.Logger.WriteCritical(guid3);
            }

            string logText = File.ReadAllText(filename);
            Assert.DoesNotContain(guid2, logText);
            Assert.Contains(guid1, logText);
            Assert.Contains(guid3, logText);

            File.Delete(filename);
        }

        [Fact]
        public void TextListenerCantAccessFileToWrite()
        {
            SampleListener listener = new SampleListener();
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);

            // default log file cannot be accessed because it is in use. Should throw an IO exception.
            string fileName = Guid.NewGuid().ToString() + ".txt";
            FileStream fileStream = File.Create(fileName);
            Assert.Throws<IOException>(() => { new TextWriterEventListener(fileName);  });
            Assert.Contains("MIML10001: ", listener.TraceBuffer);
            fileStream.Dispose();
            File.Delete(fileName);

            // file specified by user cannot be accessed.
            fileName = Guid.NewGuid().ToString() + ".txt";
            fileStream = File.Create(fileName);
            FileInfo fileInfo = new FileInfo(fileName);
            fileInfo.IsReadOnly = true;
            Assert.Throws<UnauthorizedAccessException>(() => { new TextWriterEventListener(fileName); });
            fileInfo.IsReadOnly = false;
            fileStream.Dispose();
            File.Delete(fileName);
        }

        [Fact]
        public void TextWriterEventListenerConstructors()
        {
            // using defaults
            using (TextWriterEventListener listener = new TextWriterEventListener())
            {
                IdentityModelEventSource.Logger.LogLevel = EventLevel.Informational;
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning!");
                listener.DisableEvents(IdentityModelEventSource.Logger);
            }

            string logText = File.ReadAllText(TextWriterEventListener.DefaultLogFileName);
            Assert.Contains("This is a warning!", logText);
            File.Delete(TextWriterEventListener.DefaultLogFileName);

            // passing custom file path
            var filename = Guid.NewGuid().ToString() + ".txt";
            using (TextWriterEventListener listener = new TextWriterEventListener(filename))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning for custom file path!");
                listener.DisableEvents(IdentityModelEventSource.Logger);
            }

            logText = File.ReadAllText(filename);
            Assert.Contains("This is a warning for custom file path!", logText);
            File.Delete(filename);

            // using StreamWriter
            filename = Guid.NewGuid().ToString() + ".txt";
            Stream fileStream = new FileStream(filename, FileMode.OpenOrCreate, FileAccess.Write);
            StreamWriter streamWriter = new StreamWriter(fileStream);
            using (TextWriterEventListener listener = new TextWriterEventListener(streamWriter))
            {
                listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Informational);
                IdentityModelEventSource.Logger.WriteWarning("This is a warning for streamwriter!");
                listener.DisableEvents(IdentityModelEventSource.Logger);
            }

            streamWriter.Flush();
            streamWriter.Dispose();
            logText = File.ReadAllText(filename);
            Assert.Contains("This is a warning for streamwriter!", logText);
            File.Delete(filename);
        }

        // This test will throw a FormatException if the PrepareMessage() method in IdentityModelEventSource attempts to format a message using an empty 'args' argument.
        [Fact]
        public void PrepareMessageWithNoArguments()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

             var exception = LogHelper.LogExceptionMessage(new ArgumentException("This is the first parameter '{0}'. This is the second parameter '{1}'."));
        }
    }

    class SampleListener : EventListener
    {
        public string TraceBuffer { get; set; }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData != null && eventData.Payload.Count > 0)
            {
                TraceBuffer += eventData.Payload[0] + "\n";
            }
        }
    }
}
