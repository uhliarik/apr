/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "testutil.h"
#include "apr_general.h"
#include "apr_buffer.h"
#include "apr_tables.h"

static unsigned char test_memory[] = {1, 2, 3, 4};
static char *test_string = "Hello";

static void test_memory_buffer(abts_case *tc, void *data)
{
    apr_pool_t *pool;
    apr_buffer_t *mb;
    char *str;
    void *mem;
    apr_size_t len;

    apr_pool_create(&pool, p); 

    mb = apr_buffer_mem_make(pool, test_memory, sizeof(test_memory));

    ABTS_ASSERT(tc, "mem_make stored wrong data",
                    memcmp(test_memory, mb->d.mem, sizeof(test_memory)) == 0);

    ABTS_ASSERT(tc, "memory buffer is NULL",
                    !apr_buffer_is_null(mb));

    ABTS_ASSERT(tc, "memory buffer is a string",
                    !apr_buffer_is_str(mb));

    ABTS_ASSERT(tc, "memory buffer returned a string",
                    apr_buffer_str(mb) == NULL);

    ABTS_ASSERT(tc, "memory buffer returned memory",
                    apr_buffer_mem(mb, NULL) != NULL);

    str = apr_buffer_pstrdup(pool, mb);
    ABTS_ASSERT(tc, "memory buffer returned same memory",
                    str != mb->d.mem && !memcmp(str, mb->d.mem, strlen(str)));

    mem = apr_buffer_pmemdup(pool, mb, &len);
    ABTS_ASSERT(tc, "memory buffer returned same memory",
                    mem != mb->d.mem && !memcmp(mem, mb->d.mem, len));

    ABTS_ASSERT(tc, "memory buffer has wrong length",
                    apr_buffer_len(mb) == sizeof(test_memory));

    ABTS_ASSERT(tc, "memory buffer has wrong allocation",
                    apr_buffer_allocated(mb) == sizeof(test_memory));


    apr_pool_destroy(pool);
}

static void test_string_buffer(abts_case *tc, void *data)
{
    apr_pool_t *pool;
    apr_buffer_t *sb;
    char *str;
    void *mem;
    apr_size_t len;

    apr_pool_create(&pool, p); 

    sb = apr_buffer_str_make(pool, test_string, APR_BUFFER_STRING);

    ABTS_ASSERT(tc, "str_make stored wrong data",
             strncmp(test_string, sb->d.str, strlen(test_string)) == 0);

    ABTS_ASSERT(tc, "str_make's buffer is NULL",
                    !apr_buffer_is_null(sb));

    ABTS_ASSERT(tc, "str_make's buffer is not a string",
                    apr_buffer_is_str(sb));

    ABTS_ASSERT(tc, "str_make's buffer didn't return a string",
                    apr_buffer_str(sb) != NULL);

    ABTS_ASSERT(tc, "str_make's buffer returned memory",
                    apr_buffer_mem(sb, NULL) != NULL);

    str = apr_buffer_pstrdup(pool, sb);
    ABTS_ASSERT(tc, "string buffer returned same string",
                    str != sb->d.str && !strncmp(str, sb->d.str, strlen(str)));

    mem = apr_buffer_pmemdup(pool, sb, &len);
    ABTS_ASSERT(tc, "string buffer returned same memory",
                    mem != sb->d.str && !memcmp(mem, sb->d.str, len));

    ABTS_ASSERT(tc, "string buffer has wrong length",
                    apr_buffer_len(sb) == strlen(test_string));

    ABTS_ASSERT(tc, "string buffer has wrong allocation",
                    apr_buffer_allocated(sb) == strlen(test_string) + 1);

    ABTS_ASSERT(tc, "string buffer accepted bogus non-zero terminated string",
                    APR_EINVAL == apr_buffer_str_set(sb, (char *)test_memory,
                                                     sizeof(test_memory) - 1));

    apr_pool_destroy(pool);
}

static void *test_buffers_palloc(void *ctx, apr_size_t size)
{
    apr_pool_t *pool = ctx;

    return apr_palloc(pool, size);
}

static void test_buffers(abts_case *tc, void *data)
{
    apr_pool_t *pool;
    apr_array_header_t *vals;

    apr_buffer_t src[2];
    apr_buffer_t *dst;

    char *str;
    apr_size_t len;

    memset(&src, 0, sizeof(src));

    apr_pool_create(&pool, p);

    /* populate our source buffers */
    apr_buffer_mem_set(&src[0], test_memory, sizeof(test_memory));
    apr_buffer_str_set(&src[1], test_string, strlen(test_string));

    /* duplicate the source buffers, allocating memory from a pool */
    vals = apr_array_make(pool, 2, sizeof(apr_buffer_t));
    vals->elts = (char *)apr_buffer_arraydup(src, test_buffers_palloc, pool, 2);
    vals->nelts = 2;

    dst = apr_array_pop(vals);

    ABTS_ASSERT(tc, "second buffer compare fail",
                    !apr_buffer_cmp(dst, &src[1]));

    dst = apr_array_pop(vals);

    ABTS_ASSERT(tc, "first buffer compare fail",
                    !apr_buffer_cmp(dst, &src[0]));

    dst = apr_buffer_cpy(dst, &src[1], test_buffers_palloc, pool);

    ABTS_ASSERT(tc, "buffer copy fail",
                    !apr_buffer_cmp(dst, &src[1]));

    str = apr_buffer_pstrncat(pool, &src[0], 2, "; ", APR_BUFFER_BASE64, &len);

    ABTS_ASSERT(tc, "buffer strcat fail",
                    !strcmp(str, "AQIDBA==; Hello"));

    apr_pool_destroy(pool);
}

static void test_compare_buffers(abts_case *tc, void *data)
{
    apr_pool_t *pool;
 
    apr_buffer_t *small;
    apr_buffer_t *large;
 
    char *same = "same";

    apr_pool_create(&pool, p);

    small = NULL;
    large = NULL;
    ABTS_ASSERT(tc, "NULL equals NULL",
                    !apr_buffer_cmp(small, large));

    small = apr_buffer_null_make(pool);
    ABTS_ASSERT(tc, "null buffer equals NULL",
                    !apr_buffer_cmp(small, large));

    large = apr_buffer_null_make(pool);
    ABTS_ASSERT(tc, "null buffer equals null buffer",
                    !apr_buffer_cmp(small, large));

    small = NULL;
    ABTS_ASSERT(tc, "NULL equals null buffer",
                    !apr_buffer_cmp(small, large));

    small = apr_buffer_str_make(pool, same, APR_BUFFER_STRING);
    large = apr_buffer_str_make(pool, same, APR_BUFFER_STRING);
    ABTS_ASSERT(tc, "pointer equals same pointer",
                    !apr_buffer_cmp(small, large));

    small = apr_buffer_str_make(pool, "same", APR_BUFFER_STRING);
    large = apr_buffer_str_make(pool, "same", APR_BUFFER_STRING);
    ABTS_ASSERT(tc, "'same' equals 'same'",
                    !apr_buffer_cmp(small, large));

    small = apr_buffer_str_make(pool, "short", APR_BUFFER_STRING);
    large = apr_buffer_str_make(pool, "l o n g", APR_BUFFER_STRING);
    ABTS_ASSERT(tc, "'short' less than 'l o n g'",
                    apr_buffer_cmp(small, large) < 0);
    ABTS_ASSERT(tc, "'l o n g' greater than 'short'",
                    apr_buffer_cmp(large, small) > 0);

    small = apr_buffer_str_make(pool, "aardvark", APR_BUFFER_STRING);
    large = apr_buffer_str_make(pool, "zucchini", APR_BUFFER_STRING);
    ABTS_ASSERT(tc, "'aardvark' less than 'zucchini'",
                    apr_buffer_cmp(small, large) < 0);
    ABTS_ASSERT(tc, "'zucchini' greater than 'aardvark'",
                    apr_buffer_cmp(large, small) > 0);

    apr_pool_destroy(pool);
}

abts_suite *testbuffer(abts_suite *suite)
{
    suite = ADD_SUITE(suite);

    abts_run_test(suite, test_memory_buffer, NULL);
    abts_run_test(suite, test_string_buffer, NULL);
    abts_run_test(suite, test_buffers, NULL);
    abts_run_test(suite, test_compare_buffers, NULL);

    return suite;
}
