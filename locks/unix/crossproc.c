/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2000-2001 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Apache" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

#include "apr.h"
#include "apr_strings.h"
#include "locks.h"
#include "fileio.h" /* for apr_mkstemp() */

#if APR_USE_SYSVSEM_SERIALIZE  

static struct sembuf op_on;
static struct sembuf op_off;

void apr_unix_setup_lock(void)
{
    op_on.sem_num = 0;
    op_on.sem_op = -1;
    op_on.sem_flg = SEM_UNDO;
    op_off.sem_num = 0;
    op_off.sem_op = 1;
    op_off.sem_flg = SEM_UNDO;
}

static apr_status_t lock_cleanup(void *lock_)
{
    apr_lock_t *lock=lock_;
    union semun ick;
    
    if (lock->interproc != -1) {
        ick.val = 0;
        semctl(lock->interproc, 0, IPC_RMID, ick);
    }
    return APR_SUCCESS;
}    

apr_status_t apr_unix_create_inter_lock(apr_lock_t *new)
{
    union semun ick;
    
    new->interproc = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);

    if (new->interproc < 0) {
        lock_cleanup(new);
        return errno;
    }
    ick.val = 1;
    if (semctl(new->interproc, 0, SETVAL, ick) < 0) {
        lock_cleanup(new);
        return errno;
    }
    new->curr_locked = 0;
    APR_CLEANUP_REGISTER(new, (void *)new, lock_cleanup, apr_pool_cleanup_null);
    return APR_SUCCESS;
}

apr_status_t apr_unix_lock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = semop(lock->interproc, &op_on, 1);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked = 1;
    return APR_SUCCESS;
}

apr_status_t apr_unix_unlock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = semop(lock->interproc, &op_off, 1);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked = 0;
    return APR_SUCCESS;
}

apr_status_t apr_unix_destroy_inter_lock(apr_lock_t *lock)
{
    apr_status_t stat;

    if ((stat = lock_cleanup(lock)) == APR_SUCCESS) {
        APR_CLEANUP_REMOVE(lock, lock, lock_cleanup);
        return APR_SUCCESS;
    }
    return stat;
}

apr_status_t apr_unix_child_init_lock(apr_lock_t **lock, apr_pool_t *cont, const char *fname)
{
    return APR_SUCCESS;
}

#elif (APR_USE_PROC_PTHREAD_SERIALIZE)  

void apr_unix_setup_lock(void)
{
}

static apr_status_t lock_cleanup(void *lock_)
{
    apr_lock_t *lock=lock_;
    apr_status_t stat;

    if (lock->curr_locked == 1) {
        if ((stat = pthread_mutex_unlock(lock->interproc))) {
#ifdef PTHREAD_SETS_ERRNO
            stat = errno;
#endif
            return stat;
        } 
        if (munmap((caddr_t)lock->interproc, sizeof(pthread_mutex_t))){
            return errno;
        }
    }
    return APR_SUCCESS;
}    

apr_status_t apr_unix_create_inter_lock(apr_lock_t *new)
{
    apr_status_t stat;
    int fd;
    pthread_mutexattr_t mattr;

    fd = open("/dev/zero", O_RDWR);
    if (fd < 0) {
        return errno;
    }

    new->interproc = (pthread_mutex_t *)mmap((caddr_t) 0, 
                              sizeof(pthread_mutex_t), 
                              PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); 
    if (new->interproc == (pthread_mutex_t *) (caddr_t) -1) {
        return errno;
    }
    close(fd);
    if ((stat = pthread_mutexattr_init(&mattr))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        lock_cleanup(new);
        return stat;
    }
    if ((stat = pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        lock_cleanup(new);
        return stat;
    }

    if ((stat = pthread_mutex_init(new->interproc, &mattr))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        lock_cleanup(new);
        return stat;
    }

    if ((stat = pthread_mutexattr_destroy(&mattr))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        lock_cleanup(new);
        return stat;
    }

    new->curr_locked = 0;
    APR_CLEANUP_REGISTER(new, (void *)new, lock_cleanup, apr_pool_cleanup_null);
    return APR_SUCCESS;
}

apr_status_t apr_unix_lock_inter(apr_lock_t *lock)
{
    apr_status_t stat;

    if ((stat = pthread_mutex_lock(lock->interproc))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        return stat;
    }
    lock->curr_locked = 1;
    return APR_SUCCESS;
}

apr_status_t apr_unix_unlock_inter(apr_lock_t *lock)
{
    apr_status_t stat;

    if ((stat = pthread_mutex_unlock(lock->interproc))) {
#ifdef PTHREAD_SETS_ERRNO
        stat = errno;
#endif
        return stat;
    }
    lock->curr_locked = 0;
    return APR_SUCCESS;
}

apr_status_t apr_unix_destroy_inter_lock(apr_lock_t *lock)
{
    apr_status_t stat;
    if ((stat = lock_cleanup(lock)) == APR_SUCCESS) {
        APR_CLEANUP_REMOVE(lock, lock, lock_cleanup);
        return APR_SUCCESS;
    }
    return stat;
}

apr_status_t apr_unix_child_init_lock(apr_lock_t **lock, apr_pool_t *cont, const char *fname)
{
    return APR_SUCCESS;
}

#elif (APR_USE_FCNTL_SERIALIZE)  

static struct flock lock_it;
static struct flock unlock_it;

void apr_unix_setup_lock(void)
{
    lock_it.l_whence = SEEK_SET;        /* from current point */
    lock_it.l_start = 0;                /* -"- */
    lock_it.l_len = 0;                  /* until end of file */
    lock_it.l_type = F_WRLCK;           /* set exclusive/write lock */
    lock_it.l_pid = 0;                  /* pid not actually interesting */
    unlock_it.l_whence = SEEK_SET;      /* from current point */
    unlock_it.l_start = 0;              /* -"- */
    unlock_it.l_len = 0;                /* until end of file */
    unlock_it.l_type = F_UNLCK;         /* set exclusive/write lock */
    unlock_it.l_pid = 0;                /* pid not actually interesting */
}

static apr_status_t lock_cleanup(void *lock_)
{
    apr_lock_t *lock=lock_;

    if (lock->curr_locked == 1) {
        return apr_unix_unlock_inter(lock);
    }
    return APR_SUCCESS;
}    

apr_status_t apr_unix_create_inter_lock(apr_lock_t *new)
{
    if (new->fname) {
        new->interproc = open(new->fname, O_CREAT | O_WRONLY | O_EXCL, 0644);
    }
    else {
        APR_MEM_PSTRDUP(new, new->fname, "/tmp/aprXXXXXX")
        new->interproc = apr_mkstemp(new->fname);
    }

    if (new->interproc < 0) {
        lock_cleanup(new);
        return errno;
    }

    new->curr_locked=0;
    unlink(new->fname);
    APR_CLEANUP_REGISTER(new, new, lock_cleanup, apr_pool_cleanup_null);
    return APR_SUCCESS; 
}

apr_status_t apr_unix_lock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = fcntl(lock->interproc, F_SETLKW, &lock_it);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked=1;
    return APR_SUCCESS;
}

apr_status_t apr_unix_unlock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = fcntl(lock->interproc, F_SETLKW, &unlock_it);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked=0;
    return APR_SUCCESS;
}

apr_status_t apr_unix_destroy_inter_lock(apr_lock_t *lock)
{
    apr_status_t stat;
    if ((stat = lock_cleanup(lock)) == APR_SUCCESS) {
        APR_CLEANUP_REMOVE(lock, lock, lock_cleanup);
        return APR_SUCCESS;
    }
    return stat;
}

apr_status_t apr_unix_child_init_lock(apr_lock_t **lock, apr_pool_t *cont, 
                                    const char *fname)
{
    return APR_SUCCESS;
}


#elif (APR_USE_FLOCK_SERIALIZE)

void apr_unix_setup_lock(void)
{
}

static apr_status_t lock_cleanup(void *lock_)
{
    apr_lock_t *lock=lock_;

    if (lock->curr_locked == 1) {
        return apr_unix_unlock_inter(lock);
    }
    unlink(lock->fname);
    return APR_SUCCESS;
}    

apr_status_t apr_unix_create_inter_lock(apr_lock_t *new)
{
    if (new->fname) {
        new->interproc = open(new->fname, O_CREAT | O_WRONLY | O_EXCL, 0600);
    }
    else {
        APR_MEM_PSTRDUP(new, new->fname, "/tmp/aprXXXXXX")
        new->interproc = apr_mkstemp(new->fname);
    }

    if (new->interproc < 0) {
        lock_cleanup(new);
        return errno;
    }
    new->curr_locked = 0;
    APR_CLEANUP_REGISTER(new, (void *)new, lock_cleanup, apr_pool_cleanup_null);
    return APR_SUCCESS;
}

apr_status_t apr_unix_lock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = flock(lock->interproc, LOCK_EX);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked = 1;
    return APR_SUCCESS;
}

apr_status_t apr_unix_unlock_inter(apr_lock_t *lock)
{
    int rc;

    do {
        rc = flock(lock->interproc, LOCK_UN);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0) {
        return errno;
    }
    lock->curr_locked = 0;
    return APR_SUCCESS;
}

apr_status_t apr_unix_destroy_inter_lock(apr_lock_t *lock)
{
    apr_status_t stat;
    if ((stat = lock_cleanup(lock)) == APR_SUCCESS) {
        APR_CLEANUP_REMOVE(lock, lock, lock_cleanup);
        return APR_SUCCESS;
    }
    return stat;
}

apr_status_t apr_unix_child_init_lock(apr_lock_t **lock, apr_pool_t *cont, 
                            const char *fname)
{
    apr_lock_t *new;

    new = (apr_lock_t *)apr_palloc(cont, sizeof(apr_lock_t));

    new->fname = apr_pstrdup(cont, fname);
    new->interproc = open(new->fname, O_WRONLY, 0600);
    if (new->interproc == -1) {
        apr_unix_destroy_inter_lock(new);
        return errno;
    }
    *lock = new;
    return APR_SUCCESS;
}

#else
/* No inter-process mutex on this platform.  Use at your own risk */
#define create_inter_lock(x, y)
#define lock_inter(x, y)
#define unlock_inter(x, y)
#define destroy_inter_lock(x, y)
#define child_init_lock(x, y, z)
#endif
