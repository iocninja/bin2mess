#include <stdint.h>
#include <stdio.h>

#include "xLibMaliciousApi.h"



int wmain(int argc, wchar_t* argv[])
{
	if (argc != 5)
	{
		wprintf(L"Arguments: [--aes][--xor] <full\\path\\to\\input.file> <full\\path\\to\\mess.file> <full\\path\\to\\key.file>\n");

		return 0;
	}

	const wchar_t* mode = argv[1];

	const wchar_t* fileNameIn = argv[2];
	
	const wchar_t* fileNameOut = argv[3];

	const wchar_t* fileNameKey = argv[4];

	FILE* fileIn = _wfopen(fileNameIn, L"rb");
	
	if (fileIn)
	{
		FILE* fileOut = _wfopen(fileNameOut, L"wb");

		if (fileOut)
		{
			FILE* fileKey = _wfopen(fileNameKey, L"wb");

			if (fileKey)
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

							if (wcscmp(mode, L"--aes") == 0)
							{
								uint8_t key[32];

								for (uint32_t i = 0; i < sizeof(key); i++)
								{
									key[i] = rand() % 0xff;
								}

								fwrite(key, 1, sizeof(key), fileKey);

								uint8_t* obfuscated = NULL;

								uint32_t obfuscatedSize = 0;

								if (X_LIB_MALICIOUS_CALL(xObfuscationObfuscateAes)(key, sizeof(key), plain, plainSize, &obfuscated, &obfuscatedSize))
								{
									fwrite(obfuscated, 1, obfuscatedSize, fileOut);

									X_LIB_MALICIOUS_CALL(xMemoryFree)(obfuscated);
								}
							}
							else if (wcscmp(mode, L"--xor") == 0)
							{
								uint8_t key;

								key = rand() % 0xff;

								fwrite(&key, 1, sizeof(key), fileKey);

								uint8_t* obfuscated = NULL;

								if (X_LIB_MALICIOUS_CALL(xObfuscationObfuscateXor)(key, plain, plainSize, &obfuscated))
								{
									fwrite(obfuscated, 1, plainSize, fileOut);

									X_LIB_MALICIOUS_CALL(xMemoryFree)(obfuscated);
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

				fclose(fileKey);
			}
			else
			{
				wprintf(L"Could not open key.file\n");
			}

			fclose(fileOut);
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
	
	return 0;
}