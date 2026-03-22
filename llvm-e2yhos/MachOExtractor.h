//===- MachOExtractor.h - Extração EXTREMAMENTE ROBUSTA de Mach-O p/ YHOS =//
//
// Este arquivo faz parte do conversor e2yhos para LLVM
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Extrator de arquivos Mach-O (macOS/iOS) com validação extrema, suporte a
/// Mach-O 32/64-bit, fat binaries (universal), e múltiplas arquiteturas.
///
/// Características de ROBUSTEZ:
///   - Suporte completo a Mach-O 32-bit e 64-bit
///   - Suporte a Fat Binaries (Universal Binaries)
///   - Validação rigorosa de load commands
///   - Detecção de arquivos corrompidos ou truncados
///   - Extração de segmentos (__TEXT, __DATA, __LINKEDIT)
///   - Extração de seções (__text, __data, __const, etc)
///   - Suporte a múltiplas arquiteturas (x86, x86_64, ARM, ARM64)
///   - Extração de símbolos e relocações
///   - Suporte a dyld info (bind, lazy bind, weak bind)
///   - Extração de informações de debug (DSYM, STABS)
///   - Logging detalhado e diagnóstico
///   - Limites de segurança configuráveis
///   - Recuperação heurística para arquivos danificados
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_E2YHOS_MACHOEXTRACTOR_H
#define LLVM_TOOLS_LLVM_E2YHOS_MACHOEXTRACTOR_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Optional.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/MachO.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <map>
#include <set>

namespace llvm {
namespace e2yhos {

//==============================================================================
// CONSTANTES DE SEGURANÇA E LIMITES PARA MACH-O
//==============================================================================

/// Limites máximos para Mach-O (prevenir ataques DoS)
struct MachOSecurityLimits {
  static constexpr uint32_t MAX_LOAD_COMMANDS = 4096;      // Máximo de load commands
  static constexpr uint32_t MAX_SECTIONS = 4096;           // Máximo de seções
  static constexpr uint32_t MAX_SYMBOLS = 1000000;         // Máximo de símbolos
  static constexpr uint32_t MAX_SEGMENTS = 256;            // Máximo de segmentos
  static constexpr uint32_t MAX_FAT_ARCHS = 256;           // Máximo arquiteturas em fat
  static constexpr uint64_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024; // 4GB
  static constexpr uint32_t MIN_FILE_SIZE = sizeof(MachO::mach_header); // 28 bytes
  static constexpr uint32_t MAX_SECTION_NAME_LEN = 256;
  static constexpr uint32_t MAX_SEGMENT_NAME_LEN = 32;
  static constexpr uint32_t MAX_STRING_TABLE_SIZE = 256 * 1024 * 1024; // 256MB
};

//==============================================================================
// ESTRUTURAS DE DADOS ROBUSTAS PARA MACH-O
//==============================================================================

/// Estrutura para arquitetura em fat binaries
struct RobustFatArchInfo {
  uint32_t CpuType = 0;
  uint32_t CpuSubtype = 0;
  uint64_t Offset = 0;
  uint64_t Size = 0;
  uint32_t Align = 0;
  
  std::string ArchitectureName;
  bool IsValid = false;
};

/// Estrutura para seção Mach-O
struct RobustMachOSectionInfo {
  std::string SectionName;
  std::string SegmentName;
  uint64_t Address = 0;
  uint64_t Size = 0;
  uint32_t Offset = 0;
  uint32_t Align = 0;
  uint32_t RelocOffset = 0;
  uint32_t NumRelocs = 0;
  uint32_t Flags = 0;
  uint32_t Reserved1 = 0;
  uint32_t Reserved2 = 0;
  uint32_t Reserved3 = 0;
  
  // Flags derivadas
  bool IsCode = false;
  bool IsData = false;
  bool IsConst = false;
  bool IsBss = false;
  bool IsDebug = false;
  bool IsZeroFill = false;
  bool IsThreadLocal = false;
  bool IsModInitFunc = false;
  bool IsModTermFunc = false;
  bool IsCoalesced = false;
  bool IsDeadStrippable = false;
  bool IsLiveSupport = false;
  bool IsNoDeadStrip = false;
  
  // Permissões
  bool IsReadable = true;
  bool IsWritable = false;
  bool IsExecutable = false;
  
  // Validação
  bool IsValid = false;
  bool IsTruncated = false;
  std::string ValidationError;
  
  // Dados brutos
  std::vector<uint8_t> RawData;
};

/// Estrutura para segmento Mach-O
struct RobustMachOSegmentInfo {
  std::string SegmentName;
  uint64_t VirtualAddress = 0;
  uint64_t VirtualSize = 0;
  uint64_t FileOffset = 0;
  uint64_t FileSize = 0;
  uint32_t MaxProt = 0;
  uint32_t InitProt = 0;
  uint32_t NumSections = 0;
  uint32_t Flags = 0;
  
  // Permissões derivadas
  bool IsReadable = false;
  bool IsWritable = false;
  bool IsExecutable = false;
  
  // Seções dentro do segmento
  std::vector<RobustMachOSectionInfo> Sections;
  
  // Validação
  bool IsValid = false;
  bool IsTruncated = false;
  std::string ValidationError;
};

/// Estrutura para símbolo Mach-O
struct RobustMachOSymbolInfo {
  std::string Name;
  uint64_t Value = 0;
  uint8_t Type = 0;           // N_ABS, N_SECT, N_INDR, etc
  uint8_t SectionIndex = 0;   // Section number (1-based)
  uint16_t Desc = 0;          // Description flags
  uint64_t StringTableIndex = 0;
  
  // Flags derivadas
  bool IsExternal = false;
  bool IsPrivateExternal = false;
  bool IsStab = false;         // Debug symbol
  bool IsAbsolute = false;
  bool IsIndirect = false;
  bool IsUndefined = false;
  bool IsCommon = false;
  
  // Validação
  bool IsValid = false;
};

/// Estrutura para relocação Mach-O
struct RobustMachORelocationInfo {
  uint32_t Address = 0;
  uint32_t SymbolNum = 0;
  uint8_t Type = 0;
  uint8_t Length = 0;
  bool IsPcRel = false;
  bool IsExtern = false;
  bool IsScattered = false;
  
  std::string SymbolName;
  bool IsValid = false;
};

/// Estrutura para dyld info (bind, lazy bind, weak bind)
struct RobustMachODyldInfo {
  struct BindEntry {
    uint64_t Address = 0;
    std::string SymbolName;
    uint8_t Type = 0;
    int64_t Addend = 0;
    bool IsWeak = false;
    bool IsLazy = false;
  };
  
  std::vector<BindEntry> BindOps;
  std::vector<BindEntry> LazyBindOps;
  std::vector<BindEntry> WeakBindOps;
  std::vector<uint64_t> Exports;
  
  bool HasBind = false;
  bool HasLazyBind = false;
  bool HasWeakBind = false;
  bool HasExport = false;
};

/// Estrutura para informações de debug Mach-O
struct RobustMachODebugInfo {
  bool HasStabs = false;
  bool HasDsym = false;
  bool HasDwarf = false;
  
  std::vector<uint8_t> StabData;
  std::vector<uint8_t> DwarfData;
  
  std::vector<RobustMachOSymbolInfo> StabSymbols;
  std::string DsymPath;
};

/// Dados extraídos do Mach-O com validação completa
struct RobustMachOExtractedData {
  // Cabeçalhos principais
  uint32_t Magic = 0;              // MH_MAGIC, MH_MAGIC_64, FAT_MAGIC
  uint32_t CpuType = 0;
  uint32_t CpuSubtype = 0;
  uint32_t FileType = 0;           // MH_EXECUTE, MH_DYLIB, MH_BUNDLE, etc
  uint32_t NumLoadCommands = 0;
  uint32_t SizeOfLoadCommands = 0;
  uint32_t Flags = 0;
  
  // Para 64-bit
  uint32_t Reserved = 0;
  bool Is64Bit = false;
  bool IsFatBinary = false;
  
  // Dados extraídos
  std::vector<uint8_t> CodeBuffer;
  std::vector<uint8_t> DataBuffer;
  std::vector<uint8_t_t> ConstDataBuffer;
  std::vector<uint8_t> LinkEditBuffer;
  size_t BssSize = 0;
  
  // Segmentos e seções
  std::vector<RobustMachOSegmentInfo> Segments;
  std::vector<RobustMachOSectionInfo> AllSections;
  
  // Tabelas
  std::vector<RobustMachOSymbolInfo> Symbols;
  std::vector<RobustMachORelocationInfo> Relocations;
  
  // Dyld info
  RobustMachODyldInfo DyldInfo;
  
  // Debug info
  RobustMachODebugInfo DebugInfo;
  
  // Fat binaries (universal)
  std::vector<RobustFatArchInfo> FatArchitectures;
  
  // Arquitetura selecionada (para fat)
  uint32_t SelectedArch = 0;
  
  // Informações adicionais
  std::string Identifier;           // LC_ID_DYLIB or LC_IDENT
  std::vector<std::string> Dylibs;  // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB
  std::vector<std::string> Rpaths;  // LC_RPATH
  std::vector<uint8_t> UUID;        // LC_UUID (16 bytes)
  
  // Ponto de entrada
  uint64_t EntryPoint = 0;
  uint64_t StackSize = 0;
  
  // Versões
  uint32_t MinOSVersion = 0;
  uint32_t SDKVersion = 0;
  
  // Arquitetura detectada
  uint32_t TargetArch = 0;
  
  // Estatísticas
  struct {
    uint64_t TotalRawSize = 0;
    uint32_t ValidSegments = 0;
    uint32_t ValidSections = 0;
    uint32_t ValidSymbols = 0;
    uint32_t SkippedSections = 0;
    uint32_t TruncatedSections = 0;
  } Stats;
  
  // Validação
  bool IsValid = false;
  bool IsCorrupted = false;
  bool IsStripped = false;
  std::string ValidationError;
  DiagnosticCollector Diagnostics;
};

//==============================================================================
// CLASSE PRINCIPAL - EXTRAÇÃO ROBUSTA DE MACH-O
//==============================================================================

class RobustMachOExtractor {
public:
  RobustMachOExtractor();
  ~RobustMachOExtractor();
  
  /// Extrai com validação máxima
  /// \param Buffer - Dados brutos do arquivo Mach-O
  /// \param Size - Tamanho do buffer
  /// \param Output - Estrutura para resultados
  /// \param EnableHeuristics - Habilita recuperação heurística
  /// \param ArchIndex - Índice da arquitetura para fat binaries (-1 = auto)
  /// \returns true se extração foi bem-sucedida
  bool extractRobust(const uint8_t *Buffer, size_t Size,
                     RobustMachOExtractedData &Output,
                     bool EnableHeuristics = true,
                     int ArchIndex = -1);
  
  /// Extrai de arquivo com validação máxima
  bool extractFromFileRobust(StringRef Path, RobustMachOExtractedData &Output,
                             bool EnableHeuristics = true, int ArchIndex = -1);
  
  /// Verifica integridade do arquivo Mach-O
  Error verifyIntegrity(const uint8_t *Buffer, size_t Size);
  
  /// Obtém diagnóstico detalhado
  const DiagnosticCollector& getDiagnostics() const { return Diagnostics; }
  
  /// Configura nível de verbosidade
  void setVerbose(bool Verbose) { VerboseMode = Verbose; }
  
  /// Configura limites de segurança personalizados
  void setSecurityLimits(const MachOSecurityLimits &Limits) { SecLimits = Limits; }
  
  /// Lista arquiteturas disponíveis em fat binary
  std::vector<std::string> listFatArchitectures(const uint8_t *Buffer, size_t Size);
  
  /// Obtém nome da arquitetura a partir de cpu_type/cpu_subtype
  static std::string getArchitectureName(uint32_t CpuType, uint32_t CpuSubtype);
  
  /// Mapeia CPU type para arquitetura YHOS
  static uint32_t mapMachOArchToYHOS(uint32_t CpuType, bool Is64Bit);
  
  /// Converte flags de seção Mach-O para permissões YHOS
  static uint32_t convertSectionFlagsToPermissions(uint32_t MachOFlags);
  
  /// Converte flags de segmento Mach-O para permissões YHOS
  static uint32_t convertSegmentFlagsToPermissions(uint32_t MachOProt);
  
private:
  //============================================================================
  // PROCESSAMENTO DE FAT BINARIES
  //============================================================================
  
  /// Processa fat binary (universal binary)
  Error processFatBinary(const uint8_t *Buffer, size_t Size,
                         RobustMachOExtractedData &Output,
                         int ArchIndex);
  
  /// Extrai arquitetura específica do fat binary
  Error extractFatArchitecture(const uint8_t *Buffer, size_t Size,
                               const RobustFatArchInfo &Arch,
                               RobustMachOExtractedData &Output);
  
  /// Valida cabeçalho fat
  Error validateFatHeader(const uint8_t *Buffer, size_t Size,
                          RobustMachOExtractedData &Output);
  
  //============================================================================
  // VALIDAÇÕES DE INTEGRIDADE MACH-O
  //============================================================================
  
  /// Valida cabeçalho Mach-O
  Error validateMachOHeader(const uint8_t *Buffer, size_t Size,
                            RobustMachOExtractedData &Output);
  
  /// Valida e processa load commands
  Error processLoadCommands(const uint8_t *Buffer, size_t Size,
                            RobustMachOExtractedData &Output);
  
  /// Processa comando LC_SEGMENT (32-bit)
  Error processSegmentCommand32(const uint8_t *Buffer, size_t Size,
                                uint32_t CmdOffset, uint32_t CmdSize,
                                RobustMachOExtractedData &Output);
  
  /// Processa comando LC_SEGMENT_64 (64-bit)
  Error processSegmentCommand64(const uint8_t *Buffer, size_t Size,
                                uint32_t CmdOffset, uint32_t CmdSize,
                                RobustMachOExtractedData &Output);
  
  /// Processa comando LC_SYMTAB (symbol table)
  Error processSymtabCommand(const uint8_t *Buffer, size_t Size,
                             uint32_t CmdOffset,
                             RobustMachOExtractedData &Output);
  
  /// Processa comando LC_DYSYMTAB (dynamic symbol table)
  Error processDysymtabCommand(const uint8_t *Buffer, size_t Size,
                               uint32_t CmdOffset,
                               RobustMachOExtractedData &Output);
  
  /// Processa comando LC_DYLD_INFO / LC_DYLD_INFO_ONLY
  Error processDyldInfoCommand(const uint8_t *Buffer, size_t Size,
                               uint32_t CmdOffset,
                               RobustMachOExtractedData &Output);
  
  /// Processa comando LC_LOAD_DYLIB
  Error processLoadDylibCommand(const uint8_t *Buffer, size_t Size,
                                uint32_t CmdOffset,
                                RobustMachOExtractedData &Output);
  
  /// Processa comando LC_UUID
  Error processUUIDCommand(const uint8_t *Buffer, size_t Size,
                           uint32_t CmdOffset,
                           RobustMachOExtractedData &Output);
  
  /// Processa comando LC_VERSION_MIN_* ou LC_BUILD_VERSION
  Error processVersionCommand(const uint8_t *Buffer, size_t Size,
                              uint32_t CmdOffset, uint32_t CmdType,
                              RobustMachOExtractedData &Output);
  
  /// Processa comando LC_RPATH
  Error processRpathCommand(const uint8_t *Buffer, size_t Size,
                            uint32_t CmdOffset,
                            RobustMachOExtractedData &Output);
  
  //============================================================================
  // EXTRAÇÃO DE DADOS
  //============================================================================
  
  /// Extrai dados de segmentos
  Error extractSegmentData(const uint8_t *Buffer, size_t Size,
                           RobustMachOExtractedData &Output);
  
  /// Extrai dados de seções individuais
  Error extractSectionData(const uint8_t *Buffer, size_t Size,
                           RobustMachOExtractedData &Output);
  
  /// Extrai símbolos da tabela de símbolos
  Error extractSymbols(const uint8_t *Buffer, size_t Size,
                       RobustMachOExtractedData &Output);
  
  /// Extrai relocações
  Error extractRelocations(const uint8_t *Buffer, size_t Size,
                           RobustMachOExtractedData &Output);
  
  /// Extrai dyld bind/export info
  Error extractDyldBindInfo(const uint8_t *Buffer, size_t Size,
                            RobustMachOExtractedData &Output);
  
  //============================================================================
  // PARSE DE DYLD INFO (bind/export)
  //============================================================================
  
  /// Parse bind opcodes
  Error parseBindOpcodes(const uint8_t *Buffer, size_t Size,
                         uint32_t Offset, uint32_t SizeOfData,
                         std::vector<RobustMachODyldInfo::BindEntry> &Entries,
                         bool IsLazy = false);
  
  /// Parse export trie
  Error parseExportTrie(const uint8_t *Buffer, size_t Size,
                        uint32_t Offset, uint32_t SizeOfData,
                        std::vector<uint64_t> &Exports);
  
  //============================================================================
  // HEURÍSTICAS DE RECUPERAÇÃO
  //============================================================================
  
  /// Tenta recuperar arquivo Mach-O truncado
  bool recoverTruncatedMachO(const uint8_t *Buffer, size_t &Size,
                             RobustMachOExtractedData &Output);
  
  /// Tenta recuperar cabeçalho corrompido
  bool recoverCorruptedMachOHeader(const uint8_t *Buffer, size_t Size,
                                   RobustMachOExtractedData &Output);
  
  /// Detecta Mach-O por assinatura mágica
  Optional<size_t> findMachOSignature(const uint8_t *Buffer, size_t Size);
  
  /// Tenta determinar se é 32 ou 64-bit
  bool detectMachOBitWidth(const uint8_t *Buffer, size_t Size);
  
  /// Tenta reconstruir load commands corrompidas
  bool recoverLoadCommands(const uint8_t *Buffer, size_t Size,
                           RobustMachOExtractedData &Output);
  
  //============================================================================
  // UTILITÁRIOS DE SEGURANÇA
  //============================================================================
  
  /// Verifica se offset está dentro dos limites seguros
  bool isSafeOffset(uint64_t Offset, uint64_t Size, uint64_t BufferSize) const;
  
  /// Verifica se tamanho está dentro dos limites seguros
  bool isSafeSize(uint64_t Size, uint64_t MaxSize) const;
  
  /// Leitura segura de valores com endianness (Mach-O é sempre little-endian)
  template<typename T>
  Optional<T> readSafe(const uint8_t *Buffer, uint64_t Offset, size_t BufferSize) const {
    if (!isSafeOffset(Offset, sizeof(T), BufferSize)) {
      return None;
    }
    T Value;
    memcpy(&Value, Buffer + Offset, sizeof(T));
    // Mach-O usa little-endian
    return support::endian::byte_swap<T, support::little>(Value);
  }
  
  /// Lê string terminada em null de forma segura
  std::string readStringSafe(const uint8_t *Buffer, size_t Size,
                             uint64_t Offset, uint64_t MaxLen = 1024);
  
  /// Calcula hash para validação de integridade
  uint32_t computeSimpleChecksum(const uint8_t *Buffer, size_t Size);
  
  //============================================================================
  // MEMBROS
  //============================================================================
  
  DiagnosticCollector Diagnostics;
  MachOSecurityLimits SecLimits;
  bool VerboseMode = false;
  
  // Dados temporários para extração
  uint64_t SymtabOffset = 0;
  uint64_t SymtabSize = 0;
  uint64_t StringTableOffset = 0;
  uint64_t StringTableSize = 0;
  uint64_t DysymtabOffset = 0;
  
  // Para fat binaries
  std::vector<RobustFatArchInfo> FatArchs;
  uint64_t CurrentArchOffset = 0;
  size_t CurrentArchSize = 0;
};

} // namespace e2yhos
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_E2YHOS_MACHOEXTRACTOR_H
