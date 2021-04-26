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
// all copies or substantial portions of the Software.CryptoProviderCacheOptions
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
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class EventBasedLRUCacheTests
    {
        [Fact]
        public void Contains()
        {
            TestUtilities.WriteHeader($"{this}.Contains");
            var context = new CompareContext($"{this}.Contains");
            using (var cache = new EventBasedLRUCache<int?, string>(10, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {
                cache.SetValue(1, "one");
                if (!cache.Contains(1))
                    context.AddDiff("Cache should contain the key value pair {1, 'one'}, but the Contains() method returned false.");

                cache.TryRemove(1, out _);
                if (cache.Contains(1))
                    context.AddDiff("The key value pair {1, 'one'} should have been removed from the cache, but the Contains() method returned true.");

                try
                {
                    cache.Contains(null);
                    context.AddDiff("The parameter passed into the Contains() method was null, but no exception was thrown.");
                }
                catch (Exception ex)
                {
                    if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                        context.AddDiff("The exception type thrown by Contains(null) was not of type ArgumentNullException.");
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }


        [Fact]
        public void DoNotRemoveExpiredValues()
        {
            TestUtilities.WriteHeader($"{this}.DoNotRemoveExpiredValues");
            var context = new CompareContext($"{this}.DoNotRemoveExpiredValues");
            using (var cache = new EventBasedLRUCache<int, string>(11, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, cleanUpIntervalInSeconds: 5, removeExpiredValues: false))
            {
                for (int i = 0; i <= 10; i++)
                        cache.SetValue(i, i.ToString(), DateTime.UtcNow + TimeSpan.FromSeconds(5));

                Thread.Sleep(5000);

                // expired items are not removed by default, so all added items should still be in the cache
                for (int i = 0; i <= 10; i++)
                {
                        if (!cache.Contains(i))
                            context.AddDiff("The key value pair {" + i + ", '" + i.ToString() + "'} should remain in the cache, but the Contains() method returned false.");                   
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void RemoveExpiredValues()
        {
            TestUtilities.WriteHeader($"{this}.RemoveExpiredValues");
            var context = new CompareContext($"{this}.RemoveExpiredValues");
            using (var cache = new EventBasedLRUCache<int, string>(11, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: true))
            {
                for (int i = 0; i <= 10; i++)
                {
                    // Only even values should expire.
                    if (i % 2 == 0)
                        cache.SetValue(i, i.ToString(), DateTime.UtcNow + TimeSpan.FromSeconds(5));
                    else
                        cache.SetValue(i, i.ToString());
                }

                Thread.Sleep(5000);
                cache.RemoveExpiredValues();

                for (int i = 0; i <= 10; i++)
                {
                    // Only even values should expire.
                    if (i % 2 == 0)
                    {
                        if (cache.Contains(i))
                            context.AddDiff("The key value pair {" + i + ", '" + i.ToString() + "'} should have expired and been removed, but the Contains() method returned true.");
                    }
                    else
                    {
                        if (!cache.Contains(i))
                            context.AddDiff("The key value pair {" + i + ", '" + i.ToString() + "'} should remain in the cache, but the Contains() method returned false.");
                    }
                }
                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void SetValue()
        {
            TestUtilities.WriteHeader($"{this}.SetValue");
            var context = new CompareContext($"{this}.SetValue");
            using (var cache = new EventBasedLRUCache<int?, string>(1, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {
                Assert.Throws<ArgumentNullException>(() => cache.SetValue(1, null));

                cache.SetValue(1, "one");
                if (!cache.Contains(1))
                    context.AddDiff("The key value pair {1, 'one'} should have been added to the cache, but the Contains() method returned false.");

                cache.SetValue(1, "one");
                if (!cache.Contains(1))
                    context.AddDiff("The key value pair {1, 'one'} should have been added to the cache, but the Contains() method returned false.");

                // The LRU item should be removed, allowing this value to be added even though the cache is full.
                cache.SetValue(2, "two");
                if (!cache.Contains(2))
                    context.AddDiff("The key value pair {2, 'two'} should have been added to the cache, but the Contains() method returned false.");

                try
                {
                    cache.SetValue(null, "three");
                    context.AddDiff("The first parameter passed into the SetValue() method was null, but no exception was thrown.");
                }
                catch (Exception ex)
                {
                    if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                        context.AddDiff("The exception type thrown by Set() was not of type ArgumentNullException.");
                }

                try
                {
                    cache.SetValue(3, null);
                    context.AddDiff("The second parameter passed into the SetValue() method was null, but no exception was thrown.");
                }
                catch (Exception ex)
                {
                    if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                        context.AddDiff("The exception type thrown by Set() was not of type ArgumentNullException.");
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void TryGetValue()
        {
            TestUtilities.WriteHeader($"{this}.TryGetValue");
            var context = new CompareContext($"{this}.TryGetValue");
            using (var cache = new EventBasedLRUCache<int?, string>(2, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {
                cache.SetValue(1, "one");

                if (!cache.TryGetValue(1, out var value))
                {
                    context.AddDiff("The key value pair {1, 'one'} should be in the cache, but the TryGetValue() method returned false.");
                    if (!value.Equals("one"))
                        context.AddDiff("The corresponding value for key '1' should be 'one' but was '" + value + "'.");
                }

                if (cache.TryGetValue(2, out _))
                    context.AddDiff("A key value pair with a key of '2' was never added to the cache, but the TryGetValue() method returned true.");

                try
                {
                    cache.TryGetValue(null, out _);
                    context.AddDiff("The first parameter passed into the TryGetValue() method was null, but no exception was thrown.");
                }
                catch (Exception ex)
                {
                    if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                        context.AddDiff("The exception type thrown by TryGetValue() was not of type ArgumentNullException.");
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void TryRemove()
        {
            TestUtilities.WriteHeader($"{this}.RemoveValue");
            var context = new CompareContext($"{this}.RemoveValue");
            using (var cache = new EventBasedLRUCache<int?, string>(1, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {

                cache.SetValue(1, "one");

                if (!cache.TryRemove(1, out _))
                    context.AddDiff("The key value pair {1, 'one'} should have been removed from the cache, but the TryRemove() method returned false.");

                if (cache.TryRemove(2, out _))
                    context.AddDiff("The key value pair {2, 'two'} was never added to the cache, but the TryRemove() method returned true.");

                try
                {
                    cache.TryRemove(null, out _);
                    context.AddDiff("The first parameter passed into the TryRemove() method was null, but no exception was thrown.");
                }
                catch (Exception ex)
                {
                    if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                        context.AddDiff("The exception type thrown by TryRemove() was not of type ArgumentNullException.");
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void MaintainLRUOrder()
        {
            TestUtilities.WriteHeader($"{this}.MaintainLRUOrder");
            var context = new CompareContext($"{this}.MaintainLRUOrder");
            using (var cache = new EventBasedLRUCache<int, string>(10, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {
                for (int i = 0; i <= 1000; i++)
                {
                    cache.SetValue(i, Guid.NewGuid().ToString());

                    // check that list and map values match up every 10 items
                    // every 10th item should result in two LRU items being removed
                    if (i % 10 == 0 && i != 0)
                    {
                        // wait for the cache events to process
                        cache.WaitForProcessing();

                        // wait for the last item taken from the queue to execute
                        Thread.Sleep(10);

                        // Cache size should be less than the capacity (somewhere between 8-10 items).
                        if (cache.LinkedList.Count > 10)
                            context.AddDiff("Cache size is greater than the max!");

                        // The linked list should be ordered in descending order as the largest items were added last,
                        // and therefore are most recently used.
                        if (!IsDescending(cache.LinkedList))
                        {
                            context.AddDiff("LRU order was not maintained.");
                        }
                    }
                }

                cache.WaitForProcessing();

                // wait for the last item taken from the queue to execute
                Thread.Sleep(10);

                // Cache size should be less than the capacity (somewhere between 8-10 items).
                if (cache.LinkedList.Count > 10)
                    context.AddDiff("Cache size is greater than the max!");

                // The linked list should be ordered in descending order as the largest items were added last,
                // and therefore are most recently used.
                if (!IsDescending(cache.LinkedList))
                    context.AddDiff("LRU order was not maintained.");

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact]
        public void LRUCacheItemTests()
        {
            Assert.Throws<ArgumentNullException>(() => new LRUCacheItem<string, string>("1", null));
            Assert.Throws<ArgumentNullException>(() => new LRUCacheItem<string, string>(null, "1"));
        }

        internal bool IsDescending(LinkedList<LRUCacheItem<int, string>> data)
        {
            if (data.First == null)
                return true;

            if (data.First.Next == null)
                return true;

            var prev = data.First;
            var curr = data.First.Next;
            while(curr != null)
            {
                if (prev.Value.Key < curr.Value.Key)
                {
                    return false;
                }
                prev = curr;
                curr = curr.Next;
            }

            return true;
        }

        [Fact(Skip = "Large test meant to be run manually.")]
        public void CacheOverflowTestMultithreaded()
        {
            TestUtilities.WriteHeader($"{this}.CacheOverflowTestMultithreaded");
            var context = new CompareContext($"{this}.CacheOverflowTestMultithreaded");
            using (var cache = new EventBasedLRUCache<int, string>(10, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false))
            {

                List<Task> taskList = new List<Task>();

                for (int i = 0; i < 100000; i++)
                {
                    taskList.Add(Task.Factory.StartNew(() =>
                    {
                        cache.SetValue(i, i.ToString());
                    }));
                }

                Task.WaitAll(taskList.ToArray());
                cache.WaitForProcessing();

                // Cache size should be less than the capacity (somewhere between 800 - 1000 items).
                if (cache.LinkedList.Count() > 1000)
                    context.AddDiff("Cache size is greater than the max!");

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        [Fact(Skip = "Large test meant to be run manually.")]
        public void CacheOverflowTestSequential()
        {
            TestUtilities.WriteHeader($"{this}.CacheOverflowTestSequential");
            var context = new CompareContext($"{this}.CacheOverflowTestSequential");
            var cache = new EventBasedLRUCache<int, string>(1000, TaskCreationOptions.LongRunning, tryTakeTimeout: 50, removeExpiredValues: false);

            for (int i = 0; i < 100000; i++)
            {
                cache.SetValue(i, i.ToString());
            }

            // Cache size should be less than the capacity (somewhere between 800-1000 items).
            if (cache.LinkedList.Count > 1000)
                context.AddDiff("Cache size is greater than the max!");

            // The linked list should be ordered in descending order as the largest items were added last,
            // and therefore are most recently used.
            if (!IsDescending(cache.LinkedList))
                context.AddDiff("LRU order was not maintained.");

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
