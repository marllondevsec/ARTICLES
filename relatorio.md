# RELATÓRIO TÉCNICO DE ANÁLISE DE MALWARE

## INFORMAÇÕES GERAIS

**Data da Análise:** 16 de Janeiro de 2026
**Analista:** Marllon S.
**Arquivo Analisado:** Demo_Project_LU9Z1025.exe e componentes associados
**Classificação de Risco:** **CRÍTICO**

---

## HASHS DOS ARQUIVOS

### SHA256

* `73767edc99f727c2a5feca8b752b1c0afdeab645cc8ced6f7b878d067f67cc83` — c2r64.dll
* `341ba8a556f4ac503ab23d9e5d2114261afd24aed332f2e404705b522afd5998` — Demo_Project_LU9Z1025.exe
* `53c5d4f9477b693b1a2a3d0a9a3ba4118874a4b95def426f9fbd9277163d0ec6` — AppvIsvSubsystems64.dll

### MD5

* `35ab83e566e9b1d59c5d38c4093cbcc8` — c2r64.dll
* `485a12773ab3c6350d806fce7b3d8b63` — Demo_Project_LU9Z1025.exe
* `869bda8d19d94d328ae8f2b64341e903` — AppvIsvSubsystems64.dll

---

## TAMANHOS DOS ARQUIVOS

* **c2r64.dll:** 105.003.520 bytes (~100 MB)
* **Demo_Project_LU9Z1025.exe:** 1.765.552 bytes
* **AppvIsvSubsystems64.dll:** 1.472.680 bytes

---

## ANÁLISE BINWALK

### c2r64.dll

| Offset (Dec) | Offset (Hex) | Descrição                                                                           |
| ------------ | ------------ | ----------------------------------------------------------------------------------- |
| 0            | 0x0          | Microsoft executable, portable (PE)                                                 |
| 145768       | 0x23968      | XML document, version: "1.0"                                                        |
| 13382294     | 0xCC3296     | GPG key trust database version 23                                                   |
| 16935042     | 0x1026882    | JBOOT STAG header, image id: 1, timestamp 0xBD11527F, image size: 2959714430 bytes  |
| 23586675     | 0x167E773    | JBOOT STAG header, image id: 13, timestamp 0xA9EF7D8B, image size: 3207801557 bytes |
| 41019002     | 0x271E67A    | QNX4 Boot Block                                                                     |
| 55096182     | 0x348B376    | JBOOT STAG header, image id: 9, timestamp 0x344C2D3A, image size: 3878662983 bytes  |
| 76721967     | 0x492AF2F    | JBOOT STAG header, image id: 1, timestamp 0xACA90B64, image size: 3894054751 bytes  |
| 96920445     | 0x5C6E37D    | LZ4 compressed data                                                                 |

### Demo_Project_LU9Z1025.exe

| Offset (Dec) | Offset (Hex) | Descrição                               |
| ------------ | ------------ | --------------------------------------- |
| 0            | 0x0          | Microsoft executable, portable (PE)     |
| 55760        | 0xD9D0       | PNG image, 256 x 256, 8-bit/color RGBA  |
| 223020       | 0x3672C      | PNG image, 256 x 256, 8-bit/color RGBA  |
| 440296       | 0x6B7E8      | PNG image, 256 x 256, 8-bit/color RGBA  |
| 440358       | 0x6B826      | Zlib compressed data                    |
| ...          | ...          | Múltiplas imagens PNG e dados Zlib      |
| 1613027      | 0x189CE3     | XML document, version: "1.0"            |
| 1745416      | 0x1AA208     | Object signature in DER format (PKCS#7) |

---

## ESTRUTURA PE DOS ARQUIVOS

### c2r64.dll (PE32+)

* Formato: PE32+ executable for MS Windows 6.00 (DLL), x86-64
* Seções: 7
* Seções não convencionais: `.coconut`, `.imh`, `.imh2`
* Informações de depuração:

  * **PDB path:** `D:\Project\Cpp\c2r64\x64\Release\c2r64.pdb`
  * **Signature:** `bc81defd5d7b4aed80b5ba205438776b`
  * **Age:** 28

### Demo_Project_LU9Z1025.exe (PE32+)

* Formato: PE32+ executable for MS Windows 6.01 (GUI), x86-64
* Seções: 8

### AppvIsvSubsystems64.dll (PE32+)

* Formato: PE32+ executable for MS Windows 6.01 (DLL), x86-64
* Seções: 11

---

## INFORMAÇÕES DE VERSÃO — c2r64.dll

```text
VS_VERSION_INFO
CompanyName: Ailuscajdsa
FileDescription: Sucslqweq
FileVersion: 1.24.124.4
InternalName: Sodqwrwqwe
LegalCopyright: Copyright (C) 2025
OriginalFilename: Document Ap.docx
ProductVersion: 1.221.134.32
```

---

## STRINGS SUSPEITAS DETECTADAS

```
Dots\Inter.cmd
c2r64.dll
AsDllDaylight
AsVersionablelexerEnabledEnumerate
Begin_set_impedance_Dll_Framework
Content_graph_lexer_From
CreateDll
CreateImportMacHostDll
DeletepairIPPackExecute
EightCausalityDll
EmitSegmentAmplifierHTTP
EncryptDllEncodeV
EnumerableDllSecurepressureJoin
FastRunningDll
HrGetExecutingScenario
InputDllX86
Member_HTTP_DISPATCH
NonSEPHTTPInt64
OrderMantissacacheFractionDll
PolicyconnectionNodeContentExecute
Prefix_Billboard_Dll
ProcessAccessLexerPowerBitwise
Process_Dll_pair
Reduce_Dll_Ldflda_Chance
Safe_Compaction_Control_HTTP_Save
Scan_lexer_Request
Slice_HTTP_module
Store_mode_HTTP
TempHTTPRemove
Thread_Load_weight_lexer
Type_V_INHERIT_Dll
```

---

## EVIDÊNCIAS DE MÚLTIPLOS EXECUTÁVEIS EMBUTIDOS

* **1587 cabeçalhos MZ** identificados no arquivo `c2r64.dll`.
* **Overlay criptografado de ~100 MB** com entropia **7.999998/8** (quase máxima).
* Presença de múltiplos **firmwares JBOOT STAG** para sistemas embarcados.
* Identificação de **QNX4 Boot Block** (sistema operacional de tempo real para ambientes embarcados).

---

## TÉCNICAS DE EVASÃO IDENTIFICADAS

### 1. Office Masquerading

* Disfarçado como Microsoft Word.
* Referências a caminhos PDB e binários do Office:

  * `D:\dbs\el\omr\Target\x64\ship\postc2r\x-none\winword.pdb`
  * DLLs como `mso20win32client.dll`, `mso30win32client.dll`.

### 2. DLL Sideloading

* Uso de `AppvIsvSubsystems64.dll` (DLL legítima da Microsoft).
* Carregamento indireto de `c2r64.dll` malicioso.

### 3. Packing e Ofuscação

* Overlay criptografado de 100 MB com alta entropia.
* Uso extensivo de imagens PNG e dados Zlib para ocultação de payloads.
* Container único com **1587 executáveis embutidos**.

### 4. Seções PE não-convencionais

* `.coconut`, `.imh`, `.imh2` — seções atípicas para binários Windows legítimos.

### 5. Metadados de versão falsificados

* CompanyName: `Ailuscajdsa`
* FileDescription: `Sucslqweq`
* OriginalFilename: `Document Ap.docx`

---

## FLUXO DO ATAQUE INFERIDO

1. Execução de `Demo_Project_LU9Z1025.exe` (disfarçado como Microsoft Word).
2. Carregamento de DLLs legítimas do Office para aparência legítima.
3. Sideloading de `AppvIsvSubsystems64.dll`.
4. Carregamento de `c2r64.dll` malicioso.
5. Descriptografia do overlay de ~100 MB.
6. Seleção e execução dinâmica de um entre **1587 payloads embutidos**.
7. Estabelecimento de comunicação C2 e mecanismos de persistência.

---

## INDICADORES DE COMPROMETIMENTO (IOCs)

### Hashes

**SHA256**

* 73767edc99f727c2a5feca8b752b1c0afdeab645cc8ced6f7b878d067f67cc83
* 341ba8a556f4ac503ab23d9e5d2114261afd24aed332f2e404705b522afd5998
* 53c5d4f9477b693b1a2a3d0a9a3ba4118874a4b95def426f9fbd9277163d0ec6

### Características Técnicas

* DLLs com tamanho > 50 MB (anormal para Windows).
* Seções PE: `.coconut`, `.imh`, `.imh2`.
* Arquivos contendo **1587 cabeçalhos MZ embutidos**.
* Overlay criptografado com entropia **7.999998/8**.

### Strings Relevantes

* `EncryptDllEncodeV`
* `Process_Dll_pair`
* `Store_mode_HTTP`
* `TempHTTPRemove`
* `CreateDll`

---

## CONCLUSÃO

A amostra analisada apresenta **características avançadas de APT (Advanced Persistent Threat)**, com forte ênfase em evasão, containerização massiva de payloads e indícios de direcionamento a ambientes embarcados (evidenciados por headers JBOOT e QNX). O tamanho anormal da DLL (~100 MB), combinado com a presença de **1587 executáveis embutidos** e um overlay criptografado de entropia quase máxima, indica uma ameaça altamente sofisticada, modular e multiestágio.

**Classificação:** CRÍTICO
**Recomendação:** Isolamento imediato de sistemas afetados, bloqueio dos hashes identificados e investigação forense aprofundada em ambientes comprometidos.

---

**Analista:** Marllon S.
**Data:** 16 de Janeiro de 2026
**Confidencialidade:** ALTA — Distribuição Restrita
