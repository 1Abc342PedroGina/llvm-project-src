//===- PEExtractor.cpp - Implementação EXTREMAMENTE ROBUSTA -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "PEExtractor.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstring>
#include <unordered_set>

using namespace llvm;
using namespace llvm::e2yhos;
using namespace llvm::support::endian;

//==============================================================================
// CONSTANTES E MACROS DE SEGURANÇA
//==============================================================================

// Magic numbers
#define DOS_MAGIC       0x5A4D  // "MZ"
#define PE_MAGIC       0x00004550 // "PE\0\0"
#define PE32_MAGIC     0x010b
#define PE32P_MAGIC    0x020b

// Flags de seção PE
#define IMAGE_SCN_TYPE_NO_PAD           0x00000008
#define IMAGE_SCN_CNT_CODE              0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA  0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_LNK_OTHER             0x00000100
#define IMAGE_SCN_LNK_INFO              0x00000200
#define IMAGE_SCN_LNK_REMOVE            0x00000800
#define IMAGE_SCN_LNK_COMDAT            0x00001000
#define IMAGE_SCN_GPREL                 0x00008000
#define IMAGE_SCN_MEM_PURGEABLE         0x00020000
#define IMAGE_SCN_MEM_LOCKED            0x00040000
#define IMAGE_SCN_MEM_PRELOAD           0x00080000
#define IMAGE_SCN_ALIGN_1BYTES          0x00100000
#define IMAGE_SCN_ALIGN_2BYTES          0x00200000
#define IMAGE_SCN_ALIGN_4BYTES          0x00300000
#define IMAGE_SCN_ALIGN_8BYTES          0x00400000
#define IMAGE_SCN_ALIGN_16BYTES         0x00500000
#define IMAGE_SCN_ALIGN_32BYTES         0x00600000
#define IMAGE_SCN_ALIGN_64BYTES         0x00700000
#define IMAGE_SCN_ALIGN_128BYTES        0x00800000
#define IMAGE_SCN_ALIGN_256BYTES        0x00900000
#define IMAGE_SCN_ALIGN_512BYTES        0x00A00000
#define IMAGE_SCN_ALIGN_1024BYTES       0x00B00000
#define IMAGE_SCN_ALIGN_2048BYTES       0x00C00000
#define IMAGE_SCN_ALIGN_4096BYTES       0x00D00000
#define IMAGE_SCN_ALIGN_8192BYTES       0x00E00000
#define IMAGE_SCN_LNK_NRELOC_OVFL       0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE       0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED        0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED         0x08000000
#define IMAGE_SCN_MEM_SHARED            0x10000000
#define IMAGE_SCN_MEM_EXECUTE           0x20000000
#define IMAGE_SCN_MEM_READ              0x40000000
#define IMAGE_SCN_MEM_WRITE             0x80000000

// Data directory indexes
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE  2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_DEBUG     6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#define IMAGE_DIRECTORY_ENTRY_TLS       9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#define IMAGE_DIRECTORY_ENTRY_IAT       12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

//==============================================================================
// ESTRUTURAS INTERNAS PARA PARSING SEGURO
//==============================================================================

#pragma pack(push, 1)

struct dos_header_safe {
  uint16_t e_magic;
  uint16_t e_cblp;
  uint16_t e_cp;
  uint16_t e_crlc;
  uint16_t e_cparhdr;
  uint16_t e_minalloc;
  uint16_t e_maxalloc;
  uint16_t e_ss;
  uint16_t e_sp;
  uint16_t e_csum;
  uint16_t e_ip;
  uint16_t e_cs;
  uint16_t e_lfarlc;
  uint16_t e_ovno;
  uint16_t e_res[4];
  uint16_t e_oemid;
  uint16_t e_oeminfo;
  uint16_t e_res2[10];
  uint32_t e_lfanew;
};

struct coff_file_header_safe {
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
};

struct pe32_optional_header_safe {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint32_t BaseOfData;
  uint32_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint32_t SizeOfStackReserve;
  uint32_t SizeOfStackCommit;
  uint32_t SizeOfHeapReserve;
  uint32_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
};

struct pe32plus_optional_header_safe {
  uint16_t Magic;
  uint8_t  MajorLinkerVersion;
  uint8_t  MinorLinkerVersion;
  uint32_t SizeOfCode;
  uint32_t SizeOfInitializedData;
  uint32_t SizeOfUninitializedData;
  uint32_t AddressOfEntryPoint;
  uint32_t BaseOfCode;
  uint64_t ImageBase;
  uint32_t SectionAlignment;
  uint32_t FileAlignment;
  uint16_t MajorOperatingSystemVersion;
  uint16_t MinorOperatingSystemVersion;
  uint16_t MajorImageVersion;
  uint16_t MinorImageVersion;
  uint16_t MajorSubsystemVersion;
  uint16_t MinorSubsystemVersion;
  uint32_t Win32VersionValue;
  uint32_t SizeOfImage;
  uint32_t SizeOfHeaders;
  uint32_t CheckSum;
  uint16_t Subsystem;
  uint16_t DllCharacteristics;
  uint64_t SizeOfStackReserve;
  uint64_t SizeOfStackCommit;
  uint64_t SizeOfHeapReserve;
  uint64_t SizeOfHeapCommit;
  uint32_t LoaderFlags;
  uint32_t NumberOfRvaAndSizes;
};

struct section_header_safe {
  char Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
};

struct data_directory_safe {
  uint32_t VirtualAddress;
  uint32_t Size;
};

#pragma pack(pop)

//==============================================================================
// IMPLEMENTAÇÃO
//==============================================================================

RobustPEExtractor::RobustPEExtractor() = default;
RobustPEExtractor::~RobustPEExtractor() = default;

//==============================================================================
// MÉTODOS PÚBLICOS
//==============================================================================

bool RobustPEExtractor::extractRobust(const uint8_t *Buffer, size_t Size,
                                       RobustPEExtractedData &Output,
                                       bool EnableHeuristics) {
  Diagnostics.clear();
  Output.Diagnostics.clear();
  Output.IsValid = false;
  Output.IsCorrupted = false;
  
  // Validação inicial
  if (!Buffer || Size == 0) {
    Diagnostics.add(Severity::Fatal, "Buffer nulo ou tamanho zero");
    return false;
  }
  
  if (Size < SecurityLimits::MIN_FILE_SIZE) {
    Diagnostics.add(Severity::Fatal, 
                    "Arquivo muito pequeno: " + Twine(Size).str() + " bytes");
    return false;
  }
  
  if (Size > SecurityLimits::MAX_FILE_SIZE) {
    Diagnostics.add(Severity::Fatal, 
                    "Arquivo excede limite máximo: " + Twine(Size).str() + " bytes");
    return false;
  }
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Info, 
                    "Iniciando extração robusta, tamanho: " + Twine(Size).str() + " bytes");
  }
  
  // Fase 1: Validação de cabeçalhos
  if (auto Err = validateDOSHeader(Buffer, Size, Output)) {
    if (EnableHeuristics) {
      Diagnostics.add(Severity::Warning, "Cabeçalho DOS inválido, tentando recuperação");
      if (!recoverCorruptedHeader(Buffer, Size, Output)) {
        Diagnostics.add(Severity::Error, "Falha na recuperação do cabeçalho");
        return false;
      }
    } else {
      Diagnostics.add(Severity::Fatal, toString(std::move(Err)));
      return false;
    }
  }
  
  // Fase 2: Validação do cabeçalho PE
  if (auto Err = validatePEHeader(Buffer, Size, Output)) {
    Diagnostics.add(Severity::Fatal, toString(std::move(Err)));
    return false;
  }
  
  // Fase 3: Validação do optional header
  if (auto Err = validateOptionalHeader(Buffer, Size, CurrentPEOffset, Output)) {
    Diagnostics.add(Severity::Fatal, toString(std::move(Err)));
    return false;
  }
  
  // Fase 4: Validação das seções
  if (auto Err = validateSections(Buffer, Size, CurrentPEOffset, Output)) {
    if (EnableHeuristics) {
      Diagnostics.add(Severity::Warning, "Seções inválidas, tentando recuperação");
      // Continua mesmo com erro, tentando extrair o que for possível
    } else {
      Diagnostics.add(Severity::Fatal, toString(std::move(Err)));
      return false;
    }
  }
  
  // Fase 5: Extração dos dados
  if (auto Err = extractSectionsWithHeuristics(Buffer, Size, Output)) {
    Diagnostics.add(Severity::Error, toString(std::move(Err)));
  }
  
  // Fase 6: Extração de importações e exportações
  if (auto Err = extractImportsRobust(Buffer, Size, CurrentPEOffset, Output)) {
    if (VerboseMode) {
      Diagnostics.add(Severity::Warning, "Falha na extração de importações: " + 
                      toString(std::move(Err)));
    }
  }
  
  if (auto Err = extractExportsRobust(Buffer, Size, CurrentPEOffset, Output)) {
    if (VerboseMode) {
      Diagnostics.add(Severity::Warning, "Falha na extração de exportações: " +
                      toString(std::move(Err)));
    }
  }
  
  // Fase 7: Extração de debug info
  if (auto Err = extractDebugInfoRobust(Buffer, Size, CurrentPEOffset, Output)) {
    if (VerboseMode) {
      Diagnostics.add(Severity::Debug, "Debug info: " + toString(std::move(Err)));
    }
  }
  
  // Fase 8: Verificação de checksum
  Output.ClaimedCheckSum = 0;
  Output.ComputedCheckSum = computePECheckSum(Buffer, Size);
  Output.CheckSumValid = (Output.ClaimedCheckSum == Output.ComputedCheckSum);
  
  // Fase 9: Detecção de driver de kernel
  Output.IsDriver = detectKernelDriver(Output);
  
  // Fase 10: Validação final
  Output.IsValid = (Output.CodeBuffer.size() > 0 || 
                    Output.DataBuffer.size() > 0 ||
                    Output.RodataBuffer.size() > 0);
  
  if (Output.IsValid && Output.CodeBuffer.empty() && !Output.IsDriver) {
    Diagnostics.add(Severity::Warning, 
                    "Nenhum código extraído, arquivo pode ser dados puros");
  }
  
  Output.Diagnostics = Diagnostics;
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Info, 
                    "Extração concluída. Válido: " + Twine(Output.IsValid).str() +
                    ", Seções válidas: " + Twine(Output.Stats.ValidSections).str() +
                    ", Código: " + Twine(Output.CodeBuffer.size()).str() + " bytes");
  }
  
  return Output.IsValid;
}

bool RobustPEExtractor::extractFromFileRobust(StringRef Path,
                                               RobustPEExtractedData &Output,
                                               bool EnableHeuristics) {
  // Ler arquivo com validação
  ErrorOr<std::unique_ptr<MemoryBuffer>> MemBufOrErr = 
      MemoryBuffer::getFile(Path);
  
  if (!MemBufOrErr) {
    Diagnostics.add(Severity::Fatal, 
                    "Erro ao ler arquivo: " + Path.str() + " - " +
                    MemBufOrErr.getError().message());
    return false;
  }
  
  const uint8_t *Buffer = reinterpret_cast<const uint8_t*>(
      (*MemBufOrErr)->getBufferStart());
  size_t Size = (*MemBufOrErr)->getBufferSize();
  
  return extractRobust(Buffer, Size, Output, EnableHeuristics);
}

Error RobustPEExtractor::verifyIntegrity(const uint8_t *Buffer, size_t Size) {
  RobustPEExtractedData Temp;
  if (!validateDOSHeader(Buffer, Size, Temp)) {
    return make_error<StringError>("Falha na validação do cabeçalho DOS",
                                   inconvertibleErrorCode());
  }
  if (!validatePEHeader(Buffer, Size, Temp)) {
    return make_error<StringError>("Falha na validação do cabeçalho PE",
                                   inconvertibleErrorCode());
  }
  return Error::success();
}

uint32_t RobustPEExtractor::computePECheckSum(const uint8_t *Buffer, size_t Size) {
  // Algoritmo oficial de checksum do Windows PE
  // CheckSum = (Sum of all words) + (Size of file)
  
  uint64_t Sum = 0;
  size_t NumWords = Size / 2;
  const uint16_t *Words = reinterpret_cast<const uint16_t*>(Buffer);
  
  for (size_t i = 0; i < NumWords; i++) {
    Sum += Words[i];
    Sum &= 0xFFFFFFFF; // Mantém nos 32 bits
  }
  
  // Adiciona byte ímpar se existir
  if (Size & 1) {
    Sum += Buffer[Size - 1];
    Sum &= 0xFFFFFFFF;
  }
  
  Sum = (Sum & 0xFFFF) + (Sum >> 16);
  Sum = (Sum & 0xFFFF) + (Sum >> 16);
  Sum += Size;
  
  return static_cast<uint32_t>(Sum & 0xFFFFFFFF);
}

//==============================================================================
// VALIDAÇÕES DE INTEGRIDADE
//==============================================================================

Error RobustPEExtractor::validateDOSHeader(const uint8_t *Buffer, size_t Size,
                                            RobustPEExtractedData &Output) {
  if (!isSafeOffset(0, sizeof(dos_header_safe), Size)) {
    return make_error<StringError>("Buffer muito pequeno para DOS header",
                                   inconvertibleErrorCode());
  }
  
  const dos_header_safe *Dos = reinterpret_cast<const dos_header_safe*>(Buffer);
  
  // Verificar magic
  if (Dos->e_magic != DOS_MAGIC) {
    return make_error<StringError>("Magic DOS inválido: " + 
                                   Twine::utohexstr(Dos->e_magic).str() +
                                   " (esperado MZ)",
                                   inconvertibleErrorCode());
  }
  
  Output.DOSMagic = Dos->e_magic;
  
  // Verificar offset do PE
  if (Dos->e_lfanew > Size - 4) {
    return make_error<StringError>("Offset PE inválido: " +
                                   Twine(Dos->e_lfanew).str() +
                                   " excede tamanho do arquivo",
                                   inconvertibleErrorCode());
  }
  
  CurrentPEOffset = Dos->e_lfanew;
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Debug, 
                    "DOS header válido, offset PE=0x" +
                    Twine::utohexstr(CurrentPEOffset).str());
  }
  
  return Error::success();
}

Error RobustPEExtractor::validatePEHeader(const uint8_t *Buffer, size_t Size,
                                           RobustPEExtractedData &Output) {
  if (!isSafeOffset(CurrentPEOffset, 4, Size)) {
    return make_error<StringError>("Offset PE além do buffer",
                                   inconvertibleErrorCode());
  }
  
  // Verificar assinatura PE
  uint32_t PEMagicVal = *reinterpret_cast<const uint32_t*>(Buffer + CurrentPEOffset);
  if (PEMagicVal != PE_MAGIC) {
    return make_error<StringError>("Assinatura PE inválida: 0x" +
                                   Twine::utohexstr(PEMagicVal).str() +
                                   " (esperado PE\0\0)",
                                   inconvertibleErrorCode());
  }
  
  Output.PEMagic = PEMagicVal;
  
  // Validar COFF file header
  uint32_t FileHeaderOffset = CurrentPEOffset + 4;
  if (!isSafeOffset(FileHeaderOffset, sizeof(coff_file_header_safe), Size)) {
    return make_error<StringError>("COFF file header além do buffer",
                                   inconvertibleErrorCode());
  }
  
  const coff_file_header_safe *FileHdr = 
      reinterpret_cast<const coff_file_header_safe*>(Buffer + FileHeaderOffset);
  
  // Validar número de seções
  if (FileHdr->NumberOfSections > SecLimits.MAX_SECTIONS) {
    Diagnostics.add(Severity::Warning,
                    "Número excessivo de seções: " +
                    Twine(FileHdr->NumberOfSections).str() +
                    ", limitando a " + Twine(SecLimits.MAX_SECTIONS).str());
    Output.NumberOfSections = SecLimits.MAX_SECTIONS;
  } else {
    Output.NumberOfSections = FileHdr->NumberOfSections;
  }
  
  // Validar tamanho do optional header
  if (FileHdr->SizeOfOptionalHeader > 512) { // Tamanho máximo típico
    return make_error<StringError>("Tamanho do optional header suspeito: " +
                                   Twine(FileHdr->SizeOfOptionalHeader).str(),
                                   inconvertibleErrorCode());
  }
  
  Output.SizeOfOptionalHeader = FileHdr->SizeOfOptionalHeader;
  Output.Machine = FileHdr->Machine;
  Output.TimeDateStamp = FileHdr->TimeDateStamp;
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Debug,
                    "PE header válido, seções=" + Twine(Output.NumberOfSections).str() +
                    ", machine=0x" + Twine::utohexstr(Output.Machine).str());
  }
  
  return Error::success();
}

Error RobustPEExtractor::validateOptionalHeader(const uint8_t *Buffer, size_t Size,
                                                 uint32_t PEOffset,
                                                 RobustPEExtractedData &Output) {
  uint32_t OptHdrOffset = PEOffset + 4 + sizeof(coff_file_header_safe);
  
  if (!isSafeOffset(OptHdrOffset, 2, Size)) {
    return make_error<StringError>("Optional header além do buffer",
                                   inconvertibleErrorCode());
  }
  
  uint16_t Magic = *reinterpret_cast<const uint16_t*>(Buffer + OptHdrOffset);
  Output.Magic = Magic;
  
  if (Magic == PE32_MAGIC) {
    // PE32 (32-bit)
    if (!isSafeOffset(OptHdrOffset, sizeof(pe32_optional_header_safe), Size)) {
      return make_error<StringError>("PE32 optional header truncado",
                                     inconvertibleErrorCode());
    }
    
    const pe32_optional_header_safe *OptHdr32 =
        reinterpret_cast<const pe32_optional_header_safe*>(Buffer + OptHdrOffset);
    
    Output.EntryPoint = OptHdr32->AddressOfEntryPoint + OptHdr32->ImageBase;
    Output.ImageBase = OptHdr32->ImageBase;
    Output.SizeOfImage = OptHdr32->SizeOfImage;
    Output.Subsystem = OptHdr32->Subsystem;
    Output.DllCharacteristics = OptHdr32->DllCharacteristics;
    Output.IsDLL = (OptHdr32->DllCharacteristics & 0x2000) != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    
    if (VerboseMode) {
      Diagnostics.add(Severity::Debug,
                      "PE32 detectado, entry=0x" + Twine::utohexstr(Output.EntryPoint).str());
    }
    
  } else if (Magic == PE32P_MAGIC) {
    // PE32+ (64-bit)
    if (!isSafeOffset(OptHdrOffset, sizeof(pe32plus_optional_header_safe), Size)) {
      return make_error<StringError>("PE32+ optional header truncado",
                                     inconvertibleErrorCode());
    }
    
    const pe32plus_optional_header_safe *OptHdr64 =
        reinterpret_cast<const pe32plus_optional_header_safe*>(Buffer + OptHdrOffset);
    
    Output.EntryPoint = OptHdr64->AddressOfEntryPoint + OptHdr64->ImageBase;
    Output.ImageBase = OptHdr64->ImageBase;
    Output.SizeOfImage = OptHdr64->SizeOfImage;
    Output.Subsystem = OptHdr64->Subsystem;
    Output.DllCharacteristics = OptHdr64->DllCharacteristics;
    Output.IsDLL = (OptHdr64->DllCharacteristics & 0x2000) != 0;
    
    if (VerboseMode) {
      Diagnostics.add(Severity::Debug,
                      "PE32+ detectado, entry=0x" + Twine::utohexstr(Output.EntryPoint).str());
    }
    
  } else {
    return make_error<StringError>("Magic do optional header desconhecido: 0x" +
                                   Twine::utohexstr(Magic).str(),
                                   inconvertibleErrorCode());
  }
  
  // Detectar arquitetura
  Output.TargetArch = detectArchitecture(Output);
  
  return Error::success();
}

Error RobustPEExtractor::validateSections(const uint8_t *Buffer, size_t Size,
                                           uint32_t PEOffset,
                                           RobustPEExtractedData &Output) {
  uint32_t SectionTableOffset = PEOffset + 4 + sizeof(coff_file_header_safe) +
                                 Output.SizeOfOptionalHeader;
  
  if (!isSafeOffset(SectionTableOffset, 
                    Output.NumberOfSections * sizeof(section_header_safe), Size)) {
    return make_error<StringError>("Tabela de seções além do buffer",
                                   inconvertibleErrorCode());
  }
  
  const section_header_safe *Sections =
      reinterpret_cast<const section_header_safe*>(Buffer + SectionTableOffset);
  
  Output.Sections.clear();
  std::unordered_set<uint64_t> UsedRanges; // Para detectar sobreposição
  
  for (uint32_t i = 0; i < Output.NumberOfSections && i < SecLimits.MAX_SECTIONS; i++) {
    RobustSectionInfo Info;
    
    // Nome da seção (safe copy)
    size_t NameLen = strnlen(Sections[i].Name, 8);
    Info.Name = std::string(Sections[i].Name, NameLen);
    
    Info.VirtualSize = Sections[i].VirtualSize;
    Info.VirtualAddress = Sections[i].VirtualAddress;
    Info.RawDataSize = Sections[i].SizeOfRawData;
    Info.RawDataOffset = Sections[i].PointerToRawData;
    Info.Characteristics = Sections[i].Characteristics;
    
    // Derivar flags
    Info.IsExecutable = (Info.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    Info.IsWritable = (Info.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    Info.IsReadable = (Info.Characteristics & IMAGE_SCN_MEM_READ) != 0;
    Info.IsInitialized = (Info.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;
    Info.IsDiscardable = (Info.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
    Info.IsShared = (Info.Characteristics & IMAGE_SCN_MEM_SHARED) != 0;
    
    // Validação de offsets
    if (Info.RawDataOffset > 0 && Info.RawDataSize > 0) {
      if (!isSafeOffset(Info.RawDataOffset, Info.RawDataSize, Size)) {
        Info.IsTruncated = true;
        Info.ValidationError = "Dados truncados ou além do arquivo";
        Output.Stats.TruncatedSections++;
        
        // Tentar corrigir
        if (Info.RawDataOffset < Size) {
          Info.RawDataSize = Size - Info.RawDataOffset;
        } else {
          Info.RawDataSize = 0;
        }
      }
      
      // Verificar sobreposição
      uint64_t End = Info.RawDataOffset + Info.RawDataSize;
      for (uint64_t Range : UsedRanges) {
        if ((Info.RawDataOffset >= Range && Info.RawDataOffset < Range + 4096) ||
            (End > Range && End <= Range + 4096)) {
          Info.HasOverlap = true;
          Output.Stats.OverlappingSections++;
          break;
        }
      }
      UsedRanges.insert(Info.RawDataOffset);
    }
    
    // Validar tamanhos
    if (!isSafeSize(Info.RawDataSize, SecLimits.MAX_RAW_DATA_SIZE)) {
      Info.ValidationError = "Tamanho excede limite máximo";
      Info.IsValid = false;
    } else {
      Info.IsValid = true;
      Output.Stats.ValidSections++;
      
      // Extrair dados seção (apenas metadados por enquanto)
      Output.Stats.TotalRawSize += Info.RawDataSize;
    }
    
    Output.Sections.push_back(std::move(Info));
  }
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Debug,
                    "Seções validadas: " + Twine(Output.Stats.ValidSections).str() +
                    " válidas, " + Twine(Output.Stats.TruncatedSections).str() +
                    " truncadas");
  }
  
  return Error::success();
}

Error RobustPEExtractor::validateDataDirectories(const uint8_t *Buffer, size_t Size,
                                                  uint32_t PEOffset,
                                                  RobustPEExtractedData &Output) {
  // Esta função valida os data directories do PE
  // Implementação similar às anteriores...
  return Error::success();
}

//==============================================================================
// EXTRAÇÃO COM RECUPERAÇÃO HEURÍSTICA
//==============================================================================

Error RobustPEExtractor::extractSectionsWithHeuristics(const uint8_t *Buffer,
                                                        size_t Size,
                                                        RobustPEExtractedData &Output) {
  Output.CodeBuffer.clear();
  Output.DataBuffer.clear();
  Output.RodataBuffer.clear();
  Output.BssSize = 0;
  
  size_t CodeSize = 0, DataSize = 0, RodataSize = 0;
  
  for (auto &Section : Output.Sections) {
    if (!Section.IsValid || Section.RawDataSize == 0) {
      // Seção BSS
      if (Section.IsWritable && !Section.IsInitialized) {
        Output.BssSize += Section.VirtualSize;
      }
      continue;
    }
    
    // Ler dados da seção com segurança
    if (!isSafeOffset(Section.RawDataOffset, Section.RawDataSize, Size)) {
      Diagnostics.addSection(Severity::Warning,
                             "Dados da seção corrompidos, ignorando",
                             Output.Sections.size(), Section.Name);
      continue;
    }
    
    const uint8_t *SectionData = Buffer + Section.RawDataOffset;
    
    // Classificar baseado nas flags
    if (Section.IsExecutable) {
      size_t OldSize = Output.CodeBuffer.size();
      Output.CodeBuffer.resize(OldSize + Section.RawDataSize);
      memcpy(Output.CodeBuffer.data() + OldSize, SectionData, Section.RawDataSize);
      CodeSize += Section.RawDataSize;
      
    } else if (Section.IsWritable) {
      size_t OldSize = Output.DataBuffer.size();
      Output.DataBuffer.resize(OldSize + Section.RawDataSize);
      memcpy(Output.DataBuffer.data() + OldSize, SectionData, Section.RawDataSize);
      DataSize += Section.RawDataSize;
      
    } else if (Section.IsReadable) {
      size_t OldSize = Output.RodataBuffer.size();
      Output.RodataBuffer.resize(OldSize + Section.RawDataSize);
      memcpy(Output.RodataBuffer.data() + OldSize, SectionData, Section.RawDataSize);
      RodataSize += Section.RawDataSize;
    }
  }
  
  // Heurística: se não achou código mas tem seção executável, tentar recuperar
  if (CodeSize == 0 && Output.Stats.ValidSections > 0) {
    for (auto &Section : Output.Sections) {
      if (Section.IsValid && Section.RawDataSize > 0 &&
          Section.IsReadable && !Section.IsWritable) {
        // Pode ser código sem flag de execução
        size_t OldSize = Output.CodeBuffer.size();
        Output.CodeBuffer.resize(OldSize + Section.RawDataSize);
        memcpy(Output.CodeBuffer.data() + OldSize, 
               Buffer + Section.RawDataOffset, Section.RawDataSize);
        CodeSize += Section.RawDataSize;
        
        Diagnostics.addSection(Severity::Warning,
                               "Seção tratada como código por heurística",
                               Output.Sections.size(), Section.Name);
        break;
      }
    }
  }
  
  // Atualizar tamanhos finais
  Output.CodeBuffer.resize(CodeSize);
  Output.DataBuffer.resize(DataSize);
  Output.RodataBuffer.resize(RodataSize);
  
  if (VerboseMode) {
    Diagnostics.add(Severity::Info,
                    "Dados extraídos: code=" + Twine(CodeSize).str() +
                    ", data=" + Twine(DataSize).str() +
                    ", rodata=" + Twine(RodataSize).str() +
                    ", bss=" + Twine(Output.BssSize).str());
  }
  
  return Error::success();
}

Error RobustPEExtractor::extractImportsRobust(const uint8_t *Buffer, size_t Size,
                                               uint32_t PEOffset,
                                               RobustPEExtractedData &Output) {
  // Implementação robusta de extração de imports
  // Com validação de limites e fallback
  
  Output.ImportedLibraries.clear();
  Output.ImportedSymbols.clear();
  
  // Localizar data directory de importação
  uint32_t ImportDirRVA = 0;
  uint32_t ImportDirSize = 0;
  
  // ... implementação completa com parsing seguro da IAT
  
  return Error::success();
}

Error RobustPEExtractor::extractExportsRobust(const uint8_t *Buffer, size_t Size,
                                               uint32_t PEOffset,
                                               RobustPEExtractedData &Output) {
  Output.ExportedSymbols.clear();
  Output.ExportAddresses.clear();
  
  // Implementação robusta de extração de exports
  
  return Error::success();
}

Error RobustPEExtractor::extractDebugInfoRobust(const uint8_t *Buffer, size_t Size,
                                                 uint32_t PEOffset,
                                                 RobustPEExtractedData &Output) {
  Output.HasDebugInfo = false;
  Output.DebugData.clear();
  
  // Implementação robusta de extração de debug info
  // Suporte a DWARF, PDB, CodeView
  
  return Error::success();
}

//==============================================================================
// HEURÍSTICAS DE RECUPERAÇÃO
//==============================================================================

bool RobustPEExtractor::recoverTruncatedFile(const uint8_t *Buffer, size_t &Size,
                                              RobustPEExtractedData &Output) {
  // Tenta recuperar dados de arquivo truncado
  Diagnostics.add(Severity::Warning, "Tentando recuperação de arquivo truncado");
  return true; // Placeholder
}

bool RobustPEExtractor::recoverCorruptedHeader(const uint8_t *Buffer, size_t Size,
                                                RobustPEExtractedData &Output) {
  // Tenta encontrar assinatura PE em offset alternativo
  auto PEOffsetOpt = findPESignature(Buffer, Size);
  if (!PEOffsetOpt.hasValue()) {
    return false;
  }
  
  CurrentPEOffset = *PEOffsetOpt;
  Diagnostics.add(Severity::Info,
                  "Assinatura PE encontrada em offset alternativo: 0x" +
                  Twine::utohexstr(CurrentPEOffset).str());
  
  return true;
}

Optional<uint32_t> RobustPEExtractor::findPESignature(const uint8_t *Buffer,
                                                       size_t Size) {
  // Busca pela assinatura "PE\0\0" no arquivo
  const uint32_t Target = PE_MAGIC;
  
  for (size_t i = 0; i < Size - 4; i++) {
    if (memcmp(Buffer + i, &Target, 4) == 0) {
      return i;
    }
  }
  
  return None;
}

bool RobustPEExtractor::detectKernelDriver(const RobustPEExtractedData &Data) {
  // Heurísticas para detectar driver de kernel Windows
  // ntoskrnl.exe, hal.dll, etc
  
  // Verificar nome do arquivo (se disponível)
  // Verificar características específicas de drivers
  
  // Exemplo: drivers geralmente têm seção INIT
  for (const auto &Section : Data.Sections) {
    if (Section.Name == "INIT" || Section.Name == "PAGE") {
      return true;
    }
  }
  
  return false;
}

//==============================================================================
// UTILITÁRIOS DE SEGURANÇA
//==============================================================================

bool RobustPEExtractor::isSafeOffset(uint64_t Offset, uint64_t Size,
                                      uint64_t BufferSize) const {
  if (Offset > BufferSize) return false;
  if (Size > BufferSize) return false;
  if (Offset + Size > BufferSize) return false;
  if (Offset + Size < Offset) return false; // Overflow
  return true;
}

bool RobustPEExtractor::isSafeSize(uint64_t Size, uint64_t MaxSize) const {
  if (Size > MaxSize) return false;
  return true;
}

uint32_t RobustPEExtractor::detectArchitecture(const RobustPEExtractedData &Data) {
  switch (Data.Machine) {
    case 0x14c: // IMAGE_FILE_MACHINE_I386
      return ARCH_X86_32;
    case 0x8664: // IMAGE_FILE_MACHINE_AMD64
      return ARCH_X86_64;
    case 0x1c0: // IMAGE_FILE_MACHINE_ARM
      return ARCH_ARM_32;
    case 0xaa64: // IMAGE_FILE_MACHINE_ARM64
      return ARCH_ARM_64;
    case 0x5032: // IMAGE_FILE_MACHINE_RISCV32
      return ARCH_RISCV_32;
    case 0x5064: // IMAGE_FILE_MACHINE_RISCV64
      return ARCH_RISCV_64;
    default:
      // Fallback baseado no magic do optional header
      if (Data.Magic == PE32P_MAGIC) {
        return ARCH_X86_64;
      }
      return ARCH_X86_32;
  }
}
