/*
 * A git credential helper that interface with Windows' Credential Manager
 *
 */
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <wincred.h>

/* common helpers */

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

__attribute__((format (printf, 1, 2)))
static void die(const char *err, ...)
{
	char msg[4096];
	va_list params;
	va_start(params, err);
	vsnprintf(msg, sizeof(msg), err, params);
	fprintf(stderr, "%s\n", msg);
	va_end(params);
	exit(1);
}

static void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret && !size)
		ret = malloc(1);
	if (!ret)
		 die("Out of memory");
	return ret;
}

static WCHAR *wusername, *password, *protocol, *host, *path, target[1024],
	*password_expiry_utc;

static int protect_credential_blob_as_user(LPWSTR blob, DWORD blob_length, LPWSTR *out, DWORD *out_length)
{
	if (!blob || !blob_length || !out || !out_length)
		return 0;

	DWORD error = ERROR_SUCCESS;
	*out_length = 0;

	CRED_PROTECTION_TYPE protection_type;
	BOOL result = CredProtectW(TRUE, blob, blob_length, NULL, out_length, &protection_type);

	error = GetLastError();
	if (ERROR_SUCCESS != error) {
		/* expected */
		if (ERROR_INSUFFICIENT_BUFFER == error)
			SetLastError(ERROR_SUCCESS);
		else
			return 0;
	}

	/* it should return false */
	if (FALSE != result)
		return 0;

	*out = (LPWSTR)xmalloc((*out_length) * sizeof(wchar_t));
	result = CredProtectW(TRUE, blob, blob_length, *out, out_length, &protection_type);

	if (TRUE != result)
		return 0;

	if (protection_type != CredUserProtection)
		return 0;

	return 1;
}

static int is_protected_credential_blob_as_user(LPCWSTR blob)
{
	if (!blob)
		return 0;

	CRED_PROTECTION_TYPE protection_type;
	BOOL result = CredIsProtectedW((LPWSTR)blob, &protection_type);

	/*
	 * if this API fails, it may lead to logic issues
	 * so we don't reset GetLastError
	 */
	if (ERROR_SUCCESS != GetLastError()) {
		return 0;
	}

	if (TRUE != result) {
		return 0;
	}

	if (protection_type != CredUserProtection) {
		return 0;
	}

	return 1;
}

/* assumes blob is protected, you must check by is_protected_credential_blob_as_user */
static int unprotect_credential_blob_as_user(LPCWSTR blob, DWORD blob_length, LPWSTR *out, DWORD *out_length)
{
	if (!blob || !blob_length || !out || !out_length)
		return 0;

	DWORD error = ERROR_SUCCESS;
	*out_length = 0;

	BOOL result = CredUnprotectW(TRUE, (LPWSTR)blob, blob_length, NULL, out_length);

	error = GetLastError();
	if (ERROR_SUCCESS != error) {
		/* expected */
		if (ERROR_INSUFFICIENT_BUFFER == error)
			SetLastError(ERROR_SUCCESS);
		else
			return 0;
	}

	/* it should return false */
	if (FALSE != result)
		return 0;

	*out = (LPWSTR)xmalloc((*out_length) * sizeof(wchar_t));
	result = CredUnprotectW(TRUE, (LPWSTR)blob, blob_length, *out, out_length);

	if (TRUE != result)
		return 0;

	return 1;
}

static void write_item(const char *what, LPCWSTR wbuf, int wlen)
{
	char *buf;

	if (!wbuf || !wlen) {
		printf("%s=\n", what);
		return;
	}

	int len = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, NULL, 0, NULL,
	    FALSE);
	buf = xmalloc(len);

	if (!WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, buf, len, NULL, FALSE))
		die("WideCharToMultiByte failed!");

	printf("%s=", what);
	fwrite(buf, 1, len, stdout);
	putchar('\n');
	free(buf);
}

/*
 * Match an (optional) expected string and a delimiter in the target string,
 * consuming the matched text by updating the target pointer.
 */

static LPCWSTR wcsstr_last(LPCWSTR str, LPCWSTR find)
{
	LPCWSTR res = NULL, pos;
	for (pos = wcsstr(str, find); pos; pos = wcsstr(pos + 1, find))
		res = pos;
	return res;
}

static int match_part_with_last(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim, int last)
{
	LPCWSTR delim_pos, start = *ptarget;
	int len;

	/* find start of delimiter (or end-of-string if delim is empty) */
	if (*delim)
		delim_pos = last ? wcsstr_last(start, delim) : wcsstr(start, delim);
	else
		delim_pos = start + wcslen(start);

	/*
	 * match text up to delimiter, or end of string (e.g. the '/' after
	 * host is optional if not followed by a path)
	 */
	if (delim_pos)
		len = delim_pos - start;
	else
		len = wcslen(start);

	/* update ptarget if we either found a delimiter or need a match */
	if (delim_pos || want)
		*ptarget = delim_pos ? delim_pos + wcslen(delim) : start + len;

	return !want || (!wcsncmp(want, start, len) && !want[len]);
}

static int match_part(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim)
{
	return match_part_with_last(ptarget, want, delim, 0);
}

static int match_part_last(LPCWSTR *ptarget, LPCWSTR want, LPCWSTR delim)
{
	return match_part_with_last(ptarget, want, delim, 1);
}

static int match_cred_password(const CREDENTIALW *cred) {
	int ret;
	WCHAR *cred_password = xmalloc(cred->CredentialBlobSize);
	wcsncpy_s(cred_password, cred->CredentialBlobSize,
		(LPCWSTR)cred->CredentialBlob,
		cred->CredentialBlobSize / sizeof(WCHAR));
	ret = !wcscmp(cred_password, password);
	free(cred_password);
	return ret;
}

static int match_cred(const CREDENTIALW *cred, int match_password)
{
	LPCWSTR target = cred->TargetName;
	if (wusername && wcscmp(wusername, cred->UserName ? cred->UserName : L""))
		return 0;

	return match_part(&target, L"git", L":") &&
		match_part(&target, protocol, L"://") &&
		match_part_last(&target, wusername, L"@") &&
		match_part(&target, host, L"/") &&
		match_part(&target, path, L"") &&
		(!match_password || match_cred_password(cred));
}

static void get_credential(void)
{
	CREDENTIALW **creds;
	DWORD num_creds;
	int i;
	CREDENTIAL_ATTRIBUTEW *attr;
	LPWSTR out;
	DWORD out_length;
	LPCWSTR used_password;

	out = NULL;

	if (!CredEnumerateW(L"git:*", 0, &num_creds, &creds))
		return;

	/* search for the first credential that matches username */
	for (i = 0; i < num_creds; ++i)
		if (match_cred(creds[i], 0)) {
			used_password = (LPCWSTR)creds[i]->CredentialBlob;
			if (is_protected_credential_blob_as_user(used_password)) {
				if (unprotect_credential_blob_as_user(used_password,
					creds[i]->CredentialBlobSize / sizeof(wchar_t), &out, &out_length)) {
						used_password = (LPCWSTR)out;
					}
			}

			write_item("username", creds[i]->UserName,
				creds[i]->UserName ? wcslen(creds[i]->UserName) : 0);
			write_item("password",
				used_password,
				used_password ? wcslen(used_password) : 0);
			for (int j = 0; j < creds[i]->AttributeCount; j++) {
				attr = creds[i]->Attributes + j;
				if (!wcscmp(attr->Keyword, L"git_password_expiry_utc")) {
					write_item("password_expiry_utc", (LPCWSTR)attr->Value,
					attr->ValueSize / sizeof(WCHAR));
					break;
				}
			}
			break;
		}

	CredFree(creds);
	if (out)
		free(out);
}


static void store_credential(void)
{
	CREDENTIALW cred;
	CREDENTIAL_ATTRIBUTEW expiry_attr;
	LPWSTR out;
	DWORD out_length;
	LPWSTR blob;
	DWORD blob_size;

	if (!wusername || !password)
		return;

	blob = password;
	blob_size = wcslen(password) * 2;
	int result = protect_credential_blob_as_user(password, blob_size, &out, &out_length);
	if (result) {
		blob = out;
		blob_size = out_length * 2;
	}

	cred.Flags = 0;
	cred.Type = CRED_TYPE_GENERIC;
	cred.TargetName = target;
	cred.Comment = L"saved by git-credential-wincred";
	cred.CredentialBlobSize = blob_size;
	cred.CredentialBlob = (LPVOID)blob;
	cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
	cred.AttributeCount = 0;
	cred.Attributes = NULL;
	if (password_expiry_utc != NULL) {
		expiry_attr.Keyword = L"git_password_expiry_utc";
		expiry_attr.Value = (LPVOID)password_expiry_utc;
		expiry_attr.ValueSize = (wcslen(password_expiry_utc)) * sizeof(WCHAR);
		expiry_attr.Flags = 0;
		cred.Attributes = &expiry_attr;
		cred.AttributeCount = 1;
	}
	cred.TargetAlias = NULL;
	cred.UserName = wusername;

	if (!CredWriteW(&cred, 0))
		die("CredWrite failed");
}

static void erase_credential(void)
{
	CREDENTIALW **creds;
	DWORD num_creds;
	int i;

	if (!CredEnumerateW(L"git:*", 0, &num_creds, &creds))
		return;

	for (i = 0; i < num_creds; ++i) {
		if (match_cred(creds[i], password != NULL))
			CredDeleteW(creds[i]->TargetName, creds[i]->Type, 0);
	}

	CredFree(creds);
}

static WCHAR *utf8_to_utf16_dup(const char *str)
{
	int wlen = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	WCHAR *wstr = xmalloc(sizeof(WCHAR) * wlen);
	MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, wlen);
	return wstr;
}

#define KB (1024)

static void read_credential(void)
{
	size_t alloc = 100 * KB;
	char *buf = calloc(alloc, sizeof(*buf));

	while (fgets(buf, alloc, stdin)) {
		char *v;
		size_t len = strlen(buf);
		int ends_in_newline = 0;
		/* strip trailing CR / LF */
		if (len && buf[len - 1] == '\n') {
			buf[--len] = 0;
			ends_in_newline = 1;
		}
		if (len && buf[len - 1] == '\r')
			buf[--len] = 0;

		if (!ends_in_newline)
			die("bad input: %s", buf);

		if (!*buf)
			break;

		v = strchr(buf, '=');
		if (!v)
			die("bad input: %s", buf);
		*v++ = '\0';

		if (!strcmp(buf, "protocol"))
			protocol = utf8_to_utf16_dup(v);
		else if (!strcmp(buf, "host"))
			host = utf8_to_utf16_dup(v);
		else if (!strcmp(buf, "path"))
			path = utf8_to_utf16_dup(v);
		else if (!strcmp(buf, "username")) {
			wusername = utf8_to_utf16_dup(v);
		} else if (!strcmp(buf, "password"))
			password = utf8_to_utf16_dup(v);
		else if (!strcmp(buf, "password_expiry_utc"))
			password_expiry_utc = utf8_to_utf16_dup(v);
		/*
		 * Ignore other lines; we don't know what they mean, but
		 * this future-proofs us when later versions of git do
		 * learn new lines, and the helpers are updated to match.
		 */
	}

	free(buf);
}

int main(int argc, char *argv[])
{
	const char *usage =
	    "usage: git credential-wincred <get|store|erase>\n";

	if (!argv[1])
		die("%s", usage);

	/* git use binary pipes to avoid CRLF-issues */
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);

	read_credential();

	if (!protocol || !(host || path))
		return 0;

	/* prepare 'target', the unique key for the credential */
	wcscpy(target, L"git:");
	wcsncat(target, protocol, ARRAY_SIZE(target));
	wcsncat(target, L"://", ARRAY_SIZE(target));
	if (wusername) {
		wcsncat(target, wusername, ARRAY_SIZE(target));
		wcsncat(target, L"@", ARRAY_SIZE(target));
	}
	if (host)
		wcsncat(target, host, ARRAY_SIZE(target));
	if (path) {
		wcsncat(target, L"/", ARRAY_SIZE(target));
		wcsncat(target, path, ARRAY_SIZE(target));
	}

	if (!strcmp(argv[1], "get"))
		get_credential();
	else if (!strcmp(argv[1], "store"))
		store_credential();
	else if (!strcmp(argv[1], "erase"))
		erase_credential();
	/* otherwise, ignore unknown action */
	return 0;
}
