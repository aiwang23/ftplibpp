#ifndef FTPLIB_H
#define FTPLIB_H

#define NOSSL

// windows
#ifdef  _WIN32
#include <windows.h>
#include <ctime>

#else
// unix
#include <unistd.h>
#include <sys/time.h>
#endif

//SSL
using SSL = struct ssl_st;
using SSL_CTX = struct ssl_ctx_st;
using BIO = struct bio_st;
using X509 = struct x509_st;

// 回调函数
using FtpCallbackXfer = int(*)(long xfered, void *arg);

using FtpCallbackIdle = int(*)(void *arg);

using FtpCallbackLog = void(*)(char *str, void *arg, bool out);

//SSL
using FtpCallbackCert = bool(*)(void *arg, X509 *cert);


struct ftphandle {
    char *cput, *cget;
    int handle;
    int cavail, cleft;
    char *buf;
    int dir;
    ftphandle *ctrl;
    int cmode;
    timeval idletime;
    FtpCallbackXfer xfercb;
    FtpCallbackIdle idlecb;
    FtpCallbackLog logcb;
    void *cbarg;
    long xfered;
    long cbbytes;
    long xfered1;
    char response[256];
    //SSL
    SSL *ssl;
    SSL_CTX *ctx;
    BIO *sbio;
    int tlsctrl;
    int tlsdata;
    FtpCallbackCert certcb;

    long offset;
    bool correctpasv;
};


class ftplib {
public:
    enum class accesstype {
        dir = 1,
        dirverbose,
        fileread,
        filewrite,
        filereadappend,
        filewriteappend
    };

    enum class transfermode {
        ascii = 'A',
        image = 'I'
    };

    enum class connmode {
        pasv = 1,
        port
    };

    enum class fxpmethod {
        defaultfxp = 0,
        alternativefxp
    };

    enum class dataencryption {
        unencrypted = 0,
        secure
    };

    ftplib();

    ~ftplib();

    char *LastResponse();

    int Connect(const char *host);

    int Login(const char *user, const char *pass);

    int Site(const char *cmd);

    int Raw(const char *cmd);

    int SysType(char *buf, int max);

    int Mkdir(const char *path);

    int Chdir(const char *path);

    int Cdup();

    int Rmdir(const char *path);

    int Pwd(char *path, int max);

    int Nlst(const char *outputfile, const char *path);

    int Dir(const char *outputfile, const char *path);

    int Size(const char *path, int *size, transfermode mode);

    int ModDate(const char *path, char *dt, int max);

    int Get(const char *outputfile, const char *path, transfermode mode, long offset = 0);

    int Put(const char *inputfile, const char *path, transfermode mode, long offset = 0);

    int Rename(const char *src, const char *dst);

    int Delete(const char *path);

    int Quit();

    void SetCallbackIdleFunction(FtpCallbackIdle pointer);

    void SetCallbackLogFunction(FtpCallbackLog pointer);

    void SetCallbackXferFunction(FtpCallbackXfer pointer);

    void SetCallbackArg(void *arg);

    void SetCallbackBytes(long bytes);

    void SetCorrectPasv(bool b) { mp_ftphandle->correctpasv = b; };

    void SetCallbackIdletime(int time);

    void SetConnmode(connmode mode);

    static int Fxp(ftplib *src, ftplib *dst, const char *pathSrc, const char *pathDst, transfermode mode,
                   fxpmethod method);

    ftphandle *RawOpen(const char *path, accesstype type, transfermode mode);

    int RawClose(ftphandle *handle);

    int RawWrite(void *buf, int len, ftphandle *handle);

    int RawRead(void *buf, int max, ftphandle *handle);

    // SSL
    int SetDataEncryption(dataencryption enc);

    int NegotiateEncryption();

    void SetCallbackCertFunction(FtpCallbackCert pointer);

private:
    ftphandle *mp_ftphandle;

    int FtpXfer(const char *localfile, const char *path, ftphandle *nControl, accesstype type, transfermode mode);

    int FtpOpenPasv(ftphandle *nControl, ftphandle **nData, transfermode mode, int dir, char *cmd);

    int FtpSendCmd(const char *cmd, char expresp, ftphandle *nControl);

    int FtpAcceptConnection(ftphandle *nData, ftphandle *nControl);

    int FtpOpenPort(ftphandle *nControl, ftphandle **nData, transfermode mode, int dir, char *cmd);

    int FtpRead(void *buf, int max, ftphandle *nData);

    int FtpWrite(void *buf, int len, ftphandle *nData);

    int FtpAccess(const char *path, accesstype type, transfermode mode, ftphandle *nControl, ftphandle **nData);

    int FtpClose(ftphandle *nData);

    int socket_wait(ftphandle *ctl);

    int readline(char *buf, int max, ftphandle *ctl);

    int writeline(char *buf, int len, ftphandle *nData);

    int readresp(char c, ftphandle *nControl);

    void sprint_rest(char *buf, long offset);

    void ClearHandle();

    int CorrectPasvResponse(unsigned char *v);
};

#endif
