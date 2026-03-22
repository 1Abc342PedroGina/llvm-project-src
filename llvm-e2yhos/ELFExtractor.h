//===- ELFExtractor.h - Extração EXTREMAMENTE ROBUSTA de ELF para YHOS ---===//
//
// Este arquivo faz parte do conversor e2yhos para LLVM
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Extrator de arquivos ELF (Executable and Linkable Format) com validação
/// extrema, suporte a ELF32/ELF64, múltiplas arquiteturas, e recuperação
/// de arquivos corrompidos.
///
/// Características de ROBUSTEZ:
///   - Suporte completo a ELF32 e ELF64 (Little/Big Endian)
///   - Validação rigorosa de cabeçalhos e estruturas
///   - Detecção de arquivos truncados, corrompidos ou maliciosos
///   - Suporte a múltiplas arquiteturas (x86, x86_64, ARM, ARM64, RISC-V)
///   - Extração de símbolos com validação
///   - Suporte a relocações e seções especiais
///   - Logging detalhado e diagnóstico
///   - Limites de segurança configuráveis
///   - Recuperação heurística para arquivos danificados
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_E2YHOS_ELFEXTRACTOR_H
#define LLVM_TOOLS_LLVM_E2YHOS_ELFEXTRACTOR_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Optional.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/Endian.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <map>
#include <set>

namespace llvm {
namespace e2yhos {

//==============================================================================
// CONSTANTES DE SEGURANÇA E LIMITES PARA ELF
//==============================================================================

/// Limites máximos para ELF (prevenir ataques DoS)
struct ELFSecurityLimits {
  static constexpr uint32_t MAX_SECTIONS = 65536;        // Máximo de seções ELF
  static constexpr uint32_t MAX_SEGMENTS = 65536;        // Máximo de segmentos
  static constexpr uint32_t MAX_SYMBOLS = 1000000;       // Máximo de símbolos
  static constexpr uint32_t MAX_SECTION_NAME_LEN = 256;  // Máximo nome seção
  static constexpr uint64_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024; // 4GB
  static constexpr uint32_t MIN_FILE_SIZE = sizeof(Elf32_Ehdr); // 52 bytes
  static constexpr uint32_t MAX_PHDR_ENTRIES = 1024;     // Máximo entries program header
  static constexpr uint32_t MAX_SHDR_ENTRIES = 65536;    // Máximo entries section header
  static constexpr uint32_t MAX_NOTE_SIZE = 16 * 1024 * 1024; // 16MB para notas
};

//==============================================================================
// ESTRUTURAS DE DADOS ROBUSTAS PARA ELF
//==============================================================================

/// Classe base para informações de seção ELF
struct RobustELFSectionInfo {
  std::string Name;
  uint64_t Type = 0;
  uint64_t Flags = 0;
  uint64_t Address = 0;
  uint64_t Offset = 0;
  uint64_t Size = 0;
  uint32_t Link = 0;
  uint32_t Info = 0;
  uint64_t AddrAlign = 0;
  uint64_t EntSize = 0;
  
  // Flags derivadas
  bool IsAlloc = false;
  bool IsExecutable = false;
  bool IsWritable = false;
  bool IsReadable = false;
  bool IsLoadable = false;
  bool IsDebug = false;
  bool IsStripped = false;
  
  // Validação
  bool IsValid = false;
  bool IsTruncated = false;
  bool HasOverlap = false;
  std::string ValidationError;
  
  // Dados brutos (se carregados)
  std::vector<uint8_t> RawData;
  
  RobustELFSectionInfo() = default;
};

/// Classe base para informações de segmento ELF (Program Header)
struct RobustELFProgramHeaderInfo {
  uint32_t Type = 0;
  uint32_t Flags = 0;
  uint64_t Offset = 0;
  uint64_t VAddr = 0;
  uint64_t PAddr = 0;
  uint64_t FileSize = 0;
  uint64_t MemSize = 0;
  uint64_t Align = 0;
  
  // Flags derivadas
  bool IsExecutable = false;
  bool IsWritable = false;
  bool IsReadable = false;
  bool IsLoadable = false;
  bool IsDynamic = false;
  bool IsInterp = false;
  
  // Validação
  bool IsValid = false;
  bool IsTruncated = false;
  std::string ValidationError;
  
  RobustELFProgramHeaderInfo() = default;
};

/// Informações de símbolo ELF
struct RobustELFSymbolInfo {
  std::string Name;
  uint64_t Value = 0;
  uint64_t Size = 0;
  uint8_t Bind = 0;      // STB_LOCAL, STB_GLOBAL, STB_WEAK
  uint8_t Type = 0;      // STT_NOTYPE, STT_OBJECT, STT_FUNC, etc
  uint8_t Visibility = 0; // STV_DEFAULT, STV_INTERNAL, STV_HIDDEN, STV_PROTECTED
  uint16_t SectionIndex = 0;
  
  bool IsGlobal = false;
  bool IsFunction = false;
  bool IsObject = false;
  bool IsWeak = false;
  
  // Validação
  bool IsValid = false;
  std::string ValidationError;
};

/// Informações de relocação ELF
struct RobustELFRelocationInfo {
  uint64_t Offset = 0;
  uint64_t Info = 0;
  uint64_t Addend = 0;
  uint32_t Type = 0;
  uint32_t SymbolIndex = 0;
  
  std::string SymbolName;
  bool IsValid = false;
};

/// Dados extraídos do ELF com validação completa
struct RobustELFExtractedData {
  // Cabeçalhos principais
  uint8_t EI_CLASS = 0;        // ELFCLASS32 ou ELFCLASS64
  uint8_t EI_DATA = 0;         // ELFDATA2LSB ou ELFDATA2MSB
  uint8_t EI_VERSION = 0;
  uint8_t EI_OSABI = 0;
  uint8_t EI_ABIVERSION = 0;
  
  uint16_t Type = 0;           // ET_EXEC, ET_DYN, ET_REL, ET_CORE
  uint16_t Machine = 0;        // EM_386, EM_X86_64, EM_ARM, etc
  uint32_t Version = 0;
  uint64_t EntryPoint = 0;
  
  // Tamanhos e contagens
  uint16_t ProgramHeaderCount = 0;
  uint16_t SectionHeaderCount = 0;
  uint16_t SectionHeaderStringIndex = 0;
  
  // Endianness
  bool IsLittleEndian = true;
  bool Is64Bit = false;
  
  // Dados extraídos
  std::vector<uint8_t> CodeBuffer;
  std::vector<uint8_t> DataBuffer;
  std::vector<uint8_t> RodataBuffer;
  size_t BssSize = 0;
  
  // Tabelas e seções
  std::vector<RobustELFSectionInfo> Sections;
  std::vector<RobustELFProgramHeaderInfo> ProgramHeaders;
  std::vector<RobustELFSymbolInfo> Symbols;
  std::vector<RobustELFRelocationInfo> Relocations;
  
  // Seções especiais
  std::string Interpreter;      // .interp
  std::vector<uint8_t> NoteData; // .note.*
  std::vector<uint8_t> DynamicData; // .dynamic
  
  // Informações de debug
  bool HasDebugInfo = false;
  bool HasDwarfInfo = false;
  bool HasStabInfo = false;
  std::vector<uint8_t> DebugData;
  
  // Arquitetura detectada
  uint32_t TargetArch = 0;
  
  // Estatísticas
  struct {
    uint64_t TotalRawSize = 0;
    uint32_t ValidSections = 0;
    uint32_t SkippedSections = 0;
    uint32_t TruncatedSections = 0;
    uint32_t ValidSegments = 0;
    uint32_t ValidSymbols = 0;
  } Stats;
  
  // Validação
  bool IsValid = false;
  bool IsCorrupted = false;
  std::string ValidationError;
  DiagnosticCollector Diagnostics;
  
  // Flags adicionais
  bool IsRelocatable = false;   // ET_REL
  bool IsExecutable = false;     // ET_EXEC
  bool IsSharedLib = false;      // ET_DYN
  bool IsCoreDump = false;       // ET_CORE
  bool IsStripped = false;       // Sem símbolos
  bool HasProgramHeaders = false;
  bool HasSectionHeaders = false;
};

//==============================================================================
// CLASSE PRINCIPAL - EXTRAÇÃO ROBUSTA DE ELF
//==============================================================================

class RobustELFExtractor {
public:
  RobustELFExtractor();
  ~RobustELFExtractor();
  
  /// Extrai com validação máxima
  /// \param Buffer - Dados brutos do arquivo ELF
  /// \param Size - Tamanho do buffer
  /// \param Output - Estrutura para resultados
  /// \param EnableHeuristics - Habilita recuperação heurística
  /// \returns true se extração foi bem-sucedida
  bool extractRobust(const uint8_t *Buffer, size_t Size,
                     RobustELFExtractedData &Output,
                     bool EnableHeuristics = true);
  
  /// Extrai de arquivo com validação máxima
  bool extractFromFileRobust(StringRef Path, RobustELFExtractedData &Output,
                             bool EnableHeuristics = true);
  
  /// Verifica integridade do arquivo ELF
  Error verifyIntegrity(const uint8_t *Buffer, size_t Size);
  
  /// Obtém diagnóstico detalhado
  const DiagnosticCollector& getDiagnostics() const { return Diagnostics; }
  
  /// Configura nível de verbosidade
  void setVerbose(bool Verbose) { VerboseMode = Verbose; }
  
  /// Configura limites de segurança personalizados
  void setSecurityLimits(const ELFSecurityLimits &Limits) { SecLimits = Limits; }
  
  /// Obtém informações de arquitetura
  static uint32_t mapELFArchToYHOS(uint16_t ELFMachine, bool Is64Bit);
  
  /// Converte flags de seção ELF para permissões YHOS
  static uint32_t convertSectionFlagsToPermissions(uint64_t ELFFlags);
  
  /// Converte flags de segmento ELF para permissões YHOS
  static uint32_t convertSegmentFlagsToPermissions(uint32_t ELFFlags);
  
private:
  //============================================================================
  // VALIDAÇÕES DE INTEGRIDADE
  //============================================================================
  
  /// Valida cabeçalho ELF
  Error validateELFHeader(const uint8_t *Buffer, size_t Size,
                          RobustELFExtractedData &Output);
  
  /// Valida e extrai program headers (segmentos)
  Error validateProgramHeaders(const uint8_t *Buffer, size_t Size,
                               RobustELFExtractedData &Output);
  
  /// Valida e extrai section headers
  Error validateSectionHeaders(const uint8_t *Buffer, size_t Size,
                               RobustELFExtractedData &Output);
  
  /// Valida string table de seções
  Error validateSectionStringTable(const uint8_t *Buffer, size_t Size,
                                   RobustELFExtractedData &Output);
  
  /// Valida tabela de símbolos
  Error validateSymbolTable(const uint8_t *Buffer, size_t Size,
                            RobustELFExtractedData &Output);
  
  /// Valida string table de símbolos
  Error validateSymbolStringTable(const uint8_t *Buffer, size_t Size,
                                  RobustELFExtractedData &Output);
  
  //============================================================================
  // EXTRAÇÃO DE DADOS
  //============================================================================
  
  /// Extrai dados de segmentos (PT_LOAD)
  Error extractFromProgramHeaders(const uint8_t *Buffer, size_t Size,
                                  RobustELFExtractedData &Output);
  
  /// Extrai dados de seções com heurísticas
  Error extractFromSectionsWithHeuristics(const uint8_t *Buffer, size_t Size,
                                           RobustELFExtractedData &Output);
  
  /// Extrai seções de código (.text, .init, .fini)
  Error extractCodeSections(RobustELFExtractedData &Output);
  
  /// Extrai seções de dados (.data, .data.*)
  Error extractDataSections(RobustELFExtractedData &Output);
  
  /// Extrai seções de dados somente leitura (.rodata, .rodata.*)
  Error extractRodataSections(RobustELFExtractedData &Output);
  
  /// Extrai seções BSS (.bss, .sbss)
  Error extractBssSections(RobustELFExtractedData &Output);
  
  //============================================================================
  // EXTRAÇÃO DE TABELAS ESPECIAIS
  //============================================================================
  
  /// Extrai tabela de símbolos com validação
  Error extractSymbolsRobust(const uint8_t *Buffer, size_t Size,
                             RobustELFExtractedData &Output);
  
  /// Extrai relocações
  Error extractRelocationsRobust(const uint8_t *Buffer, size_t Size,
                                 RobustELFExtractedData &Output);
  
  /// Extrai notas ELF (.note.*)
  Error extractNotesRobust(const uint8_t *Buffer, size_t Size,
                           RobustELFExtractedData &Output);
  
  /// Extrai seção .dynamic
  Error extractDynamicSection(const uint8_t *Buffer, size_t Size,
                              RobustELFExtractedData &Output);
  
  /// Extrai seção .interp (interpreter)
  Error extractInterpreterSection(const uint8_t *Buffer, size_t Size,
                                  RobustELFExtractedData &Output);
  
  //============================================================================
  // EXTRAÇÃO DE DEBUG INFO
  //============================================================================
  
  /// Extrai informações de debug (DWARF, STABS)
  Error extractDebugInfoRobust(const uint8_t *Buffer, size_t Size,
                               RobustELFExtractedData &Output);
  
  /// Detecta seções de debug DWARF
  bool isDwarfSection(const std::string &Name);
  
  /// Detecta seções de debug STABS
  bool isStabSection(const std::string &Name);
  
  //============================================================================
  // HEURÍSTICAS DE RECUPERAÇÃO
  //============================================================================
  
  /// Tenta recuperar arquivo ELF truncado
  bool recoverTruncatedELF(const uint8_t *Buffer, size_t &Size,
                           RobustELFExtractedData &Output);
  
  /// Tenta recuperar cabeçalho corrompido
  bool recoverCorruptedELFHeader(const uint8_t *Buffer, size_t Size,
                                 RobustELFExtractedData &Output);
  
  /// Detecta ELF por assinatura mágica
  Optional<size_t> findELFSignature(const uint8_t *Buffer, size_t Size);
  
  /// Tenta determinar endianness automaticamente
  bool detectEndianness(const uint8_t *Buffer, size_t Size);
  
  /// Tenta determinar classe (32/64-bit) automaticamente
  bool detectClass(const uint8_t *Buffer, size_t Size);
  
  //============================================================================
  // UTILITÁRIOS DE SEGURANÇA
  //============================================================================
  
  /// Verifica se offset está dentro dos limites seguros
  bool isSafeOffset(uint64_t Offset, uint64_t Size, uint64_t BufferSize) const;
  
  /// Verifica se tamanho está dentro dos limites seguros
  bool isSafeSize(uint64_t Size, uint64_t MaxSize) const;
  
  /// Leitura segura de valores com endianness
  template<typename T>
  Optional<T> readSafe(const uint8_t *Buffer, uint64_t Offset, 
                       size_t BufferSize, bool IsLittleEndian) const {
    if (!isSafeOffset(Offset, sizeof(T), BufferSize)) {
      return None;
    }
    T Value;
    memcpy(&Value, Buffer + Offset, sizeof(T));
    if (IsLittleEndian) {
      return support::endian::byte_swap<T, support::little>(Value);
    } else {
      return support::endian::byte_swap<T, support::big>(Value);
    }
  }
  
  /// Obtém nome da seção de forma segura
  std::string getSectionNameSafe(const uint8_t *Buffer, size_t Size,
                                 uint32_t Index, 
                                 const RobustELFExtractedData &Output);
  
  //============================================================================
  // MEMBROS
  //============================================================================
  
  DiagnosticCollector Diagnostics;
  ELFSecurityLimits SecLimits;
  bool VerboseMode = false;
  
  // Endianness e classe detectadas
  bool DetectedLittleEndian = true;
  bool Detected64Bit = true;
  
  // Offsets calculados
  uint64_t ELFHeaderOffset = 0;
  uint64_t ProgramHeaderOffset = 0;
  uint64_t SectionHeaderOffset = 0;
  uint64_t SectionStringTableOffset = 0;
  uint64_t SymbolTableOffset = 0;
  uint64_t SymbolStringTableOffset = 0;
};

} // namespace e2yhos
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_E2YHOS_ELFEXTRACTOR_H
