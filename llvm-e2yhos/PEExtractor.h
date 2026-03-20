//===- PEExtractor.h - Extração EXTREMAMENTE ROBUSTA de PE para YHOS -----===//
//
//   Copyright (C) 2026 Pedro Emanuel
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Affero General Public License as
//    published by the Free Software Foundation, either version 3 of the
//    License, or (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Affero General Public License for more details.
//
//    You should have received a copy of the GNU Affero General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Extrator de arquivos PE/COFF com validação extrema, suporte a arquivos
/// corrompidos, recuperação de erros, e logging detalhado.
///
/// Características de ROBUSTEZ:
///   - Validação em múltiplos níveis (assinaturas, checksums, integridade)
///   - Recuperação de erros com fallback para análise heurística
///   - Proteção contra arquivos malformados (buffer overflow, loops infinitos)
///   - Suporte a PE32, PE32+, PE32+ com endereçamento híbrido
///   - Detecção de arquivos truncados, corrompidos ou maliciosos
///   - Logging detalhado para debug
///   - Limites de segurança (máximo de seções, tamanhos, etc)
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_E2YHOS_PEEXTRACTOR_H
#define LLVM_TOOLS_LLVM_E2YHOS_PEEXTRACTOR_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/Optional.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Error.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <set>

namespace llvm {
namespace e2yhos {

//==============================================================================
// CONSTANTES DE SEGURANÇA E LIMITES
//==============================================================================

/// Limites máximos para prevenir ataques DoS e arquivos maliciosos
struct SecurityLimits {
  static constexpr uint32_t MAX_SECTIONS = 256;           // Máximo de seções PE
  static constexpr uint32_t MAX_SYMBOLS = 100000;         // Máximo de símbolos
  static constexpr uint32_t MAX_IMPORT_LIBS = 4096;       // Máximo de libs importadas
  static constexpr uint32_t MAX_EXPORT_SYMS = 65536;      // Máximo de símbolos exportados
  static constexpr uint64_t MAX_CODE_SIZE = 1024ULL * 1024 * 1024; // 1GB
  static constexpr uint64_t MAX_DATA_SIZE = 2ULL * 1024 * 1024 * 1024; // 2GB
  static constexpr uint32_t MIN_FILE_SIZE = sizeof(dos_header); // 64 bytes
  static constexpr uint32_t MAX_FILE_SIZE = 4ULL * 1024 * 1024 * 1024; // 4GB
  static constexpr uint32_t MAX_SECTION_NAME_LEN = 256;
  static constexpr uint32_t MAX_RAW_DATA_SIZE = 2ULL * 1024 * 1024 * 1024; // 2GB
};

//==============================================================================
// ESTRUTURAS DE DADOS ROBUSTAS
//==============================================================================

/// Níveis de severidade para diagnóstico
enum class Severity {
  Debug,      // Informação de debug
  Info,       // Informação geral
  Warning,    // Aviso (não fatal)
  Error,      // Erro recuperável
  Fatal       // Erro fatal
};

/// Estrutura para logging detalhado
struct DiagnosticInfo {
  Severity Level;
  std::string Message;
  Optional<uint64_t> Offset;     // Offset no arquivo onde ocorreu
  Optional<uint32_t> SectionIdx; // Índice da seção relacionada
  Optional<std::string> SectionName;
  
  DiagnosticInfo(Severity Lvl, const std::string& Msg)
      : Level(Lvl), Message(Msg) {}
  
  DiagnosticInfo(Severity Lvl, const std::string& Msg, uint64_t Off)
      : Level(Lvl), Message(Msg), Offset(Off) {}
  
  std::string toString() const {
    std::string Prefix;
    switch (Level) {
      case Severity::Debug:   Prefix = "[DEBUG] "; break;
      case Severity::Info:    Prefix = "[INFO]  "; break;
      case Severity::Warning: Prefix = "[WARN]  "; break;
      case Severity::Error:   Prefix = "[ERROR] "; break;
      case Severity::Fatal:   Prefix = "[FATAL] "; break;
    }
    
    std::string Result = Prefix + Message;
    if (Offset.hasValue()) {
      Result += " [offset=0x" + Twine::utohexstr(*Offset).str() + "]";
    }
    if (SectionIdx.hasValue()) {
      Result += " [section=" + Twine(*SectionIdx).str() + "]";
      if (SectionName.hasValue()) {
        Result += " (" + *SectionName + ")";
      }
    }
    return Result;
  }
};

/// Estrutura de diagnóstico com histórico
class DiagnosticCollector {
private:
  std::vector<DiagnosticInfo> Diagnostics;
  bool HasFatal = false;
  bool HasError = false;
  uint32_t MaxDiagnostics = 1000; // Limite para evitar spam
  
public:
  void add(Severity Level, const std::string& Message) {
    if (Diagnostics.size() >= MaxDiagnostics) return;
    Diagnostics.emplace_back(Level, Message);
    if (Level == Severity::Error) HasError = true;
    if (Level == Severity::Fatal) HasFatal = true;
  }
  
  void add(Severity Level, const std::string& Message, uint64_t Offset) {
    if (Diagnostics.size() >= MaxDiagnostics) return;
    Diagnostics.emplace_back(Level, Message, Offset);
    if (Level == Severity::Error) HasError = true;
    if (Level == Severity::Fatal) HasFatal = true;
  }
  
  void addSection(Severity Level, const std::string& Message, 
                  uint32_t Idx, const std::string& Name) {
    if (Diagnostics.size() >= MaxDiagnostics) return;
    DiagnosticInfo Diag(Level, Message);
    Diag.SectionIdx = Idx;
    Diag.SectionName = Name;
    Diagnostics.push_back(Diag);
    if (Level == Severity::Error) HasError = true;
    if (Level == Severity::Fatal) HasFatal = true;
  }
  
  bool hasFatal() const { return HasFatal; }
  bool hasError() const { return HasError; }
  
  void print(raw_ostream &OS) const {
    for (const auto &Diag : Diagnostics) {
      OS << Diag.toString() << "\n";
    }
  }
  
  void clear() {
    Diagnostics.clear();
    HasFatal = false;
    HasError = false;
  }
  
  std::vector<DiagnosticInfo> getDiagnostics() const { return Diagnostics; }
};

/// Informações detalhadas de seção com validação
struct RobustSectionInfo {
  std::string Name;
  uint64_t VirtualAddress = 0;
  uint64_t VirtualSize = 0;
  uint64_t RawDataOffset = 0;
  uint64_t RawDataSize = 0;
  uint32_t Characteristics = 0;
  
  // Flags derivadas
  bool IsExecutable = false;
  bool IsWritable = false;
  bool IsReadable = false;
  bool IsInitialized = false;
  bool IsDiscardable = false;
  bool IsShared = false;
  
  // Validação
  bool IsValid = false;
  bool IsTruncated = false;
  bool HasOverlap = false;
  std::string ValidationError;
  
  // Dados brutos (se carregados)
  std::vector<uint8_t> RawData; // Apenas se necessário
  
  RobustSectionInfo() = default;
};

/// Dados extraídos com validação completa
struct RobustPEExtractedData {
  // Cabeçalhos originais
  uint32_t DOSMagic = 0;
  uint32_t PEMagic = 0;
  uint16_t Machine = 0;
  uint16_t NumberOfSections = 0;
  uint32_t SizeOfOptionalHeader = 0;
  uint16_t Magic = 0; // 0x10b = PE32, 0x20b = PE32+
  
  // Dados extraídos
  std::vector<uint8_t> CodeBuffer;
  std::vector<uint8_t> DataBuffer;
  std::vector<uint8_t> RodataBuffer;
  size_t BssSize = 0;
  
  // Metadados
  uint64_t EntryPoint = 0;
  uint64_t ImageBase = 0;
  uint32_t SizeOfImage = 0;
  uint16_t Subsystem = 0;
  uint32_t DllCharacteristics = 0;
  uint32_t TargetArch = 0;
  bool IsDLL = false;
  bool IsDriver = false;
  
  // Tabelas
  std::vector<RobustSectionInfo> Sections;
  std::vector<std::string> ImportedLibraries;
  std::vector<std::string> ImportedSymbols;
  std::vector<std::string> ExportedSymbols;
  std::vector<uint64_t> ExportAddresses;
  std::set<std::string> UniqueImportedLibs;
  
  // Debug
  bool HasDebugInfo = false;
  uint32_t DebugDataSize = 0;
  std::vector<uint8_t> DebugData;
  
  // Checksums
  uint32_t ClaimedCheckSum = 0;
  uint32_t ComputedCheckSum = 0;
  bool CheckSumValid = false;
  
  // Timestamp
  uint32_t TimeDateStamp = 0;
  
  // Validação
  bool IsValid = false;
  bool IsCorrupted = false;
  std::string ValidationError;
  DiagnosticCollector Diagnostics;
  
  // Estatísticas
  struct {
    uint64_t TotalRawSize = 0;
    uint32_t ValidSections = 0;
    uint32_t SkippedSections = 0;
    uint32_t TruncatedSections = 0;
    uint32_t OverlappingSections = 0;
  } Stats;
};

//==============================================================================
// CLASSE PRINCIPAL - EXTREMAMENTE ROBUSTA
//==============================================================================

class RobustPEExtractor {
public:
  RobustPEExtractor();
  ~RobustPEExtractor();
  
  /// Extrai com validação máxima
  /// \param Buffer - Dados brutos do arquivo PE
  /// \param Size - Tamanho do buffer
  /// \param Output - Estrutura para resultados
  /// \param EnableHeuristics - Habilita recuperação heurística
  /// \returns true se extração foi bem-sucedida (parcialmente ou totalmente)
  bool extractRobust(const uint8_t *Buffer, size_t Size, 
                     RobustPEExtractedData &Output,
                     bool EnableHeuristics = true);
  
  /// Extrai de arquivo com validação máxima
  bool extractFromFileRobust(StringRef Path, RobustPEExtractedData &Output,
                             bool EnableHeuristics = true);
  
  /// Verifica integridade do arquivo PE
  /// \returns Error::success() se integridade confirmada
  Error verifyIntegrity(const uint8_t *Buffer, size_t Size);
  
  /// Calcula checksum do arquivo PE (algoritmo PE oficial)
  uint32_t computePECheckSum(const uint8_t *Buffer, size_t Size);
  
  /// Obtém diagnóstico detalhado
  const DiagnosticCollector& getDiagnostics() const { return Diagnostics; }
  
  /// Configura nível de verbosidade
  void setVerbose(bool Verbose) { VerboseMode = Verbose; }
  
  /// Configura limites de segurança personalizados
  void setSecurityLimits(const SecurityLimits &Limits) { SecLimits = Limits; }
  
private:
  //============================================================================
  // VALIDAÇÕES DE INTEGRIDADE
  //============================================================================
  
  /// Valida cabeçalho DOS
  Error validateDOSHeader(const uint8_t *Buffer, size_t Size, 
                          RobustPEExtractedData &Output);
  
  /// Valida cabeçalho PE
  Error validatePEHeader(const uint8_t *Buffer, size_t Size,
                         RobustPEExtractedData &Output);
  
  /// Valida optional header
  Error validateOptionalHeader(const uint8_t *Buffer, size_t Size,
                               uint32_t PEOffset,
                               RobustPEExtractedData &Output);
  
  /// Valida tabela de seções com detecção de sobreposição
  Error validateSections(const uint8_t *Buffer, size_t Size,
                         uint32_t PEOffset,
                         RobustPEExtractedData &Output);
  
  /// Valida data directories
  Error validateDataDirectories(const uint8_t *Buffer, size_t Size,
                                uint32_t PEOffset,
                                RobustPEExtractedData &Output);
  
  //============================================================================
  // EXTRAÇÃO COM RECUPERAÇÃO HEURÍSTICA
  //============================================================================
  
  /// Extrai seções com fallback para seções corrompidas
  Error extractSectionsWithHeuristics(const uint8_t *Buffer, size_t Size,
                                       RobustPEExtractedData &Output);
  
  /// Extrai tabela de importação com validação
  Error extractImportsRobust(const uint8_t *Buffer, size_t Size,
                             uint32_t PEOffset,
                             RobustPEExtractedData &Output);
  
  /// Extrai tabela de exportação com validação
  Error extractExportsRobust(const uint8_t *Buffer, size_t Size,
                             uint32_t PEOffset,
                             RobustPEExtractedData &Output);
  
  /// Extrai informações de debug (DWARF, PDB, CodeView)
  Error extractDebugInfoRobust(const uint8_t *Buffer, size_t Size,
                               uint32_t PEOffset,
                               RobustPEExtractedData &Output);
  
  //============================================================================
  // HEURÍSTICAS DE RECUPERAÇÃO
  //============================================================================
  
  /// Tenta recuperar arquivo truncado
  bool recoverTruncatedFile(const uint8_t *Buffer, size_t &Size,
                            RobustPEExtractedData &Output);
  
  /// Tenta recuperar cabeçalho corrompido
  bool recoverCorruptedHeader(const uint8_t *Buffer, size_t Size,
                              RobustPEExtractedData &Output);
  
  /// Detecta formato PE por assinatura em offset variável
  Optional<uint32_t> findPESignature(const uint8_t *Buffer, size_t Size);
  
  /// Detecta se é driver de kernel (ntoskrnl.exe, etc)
  bool detectKernelDriver(const RobustPEExtractedData &Data);
  
  //============================================================================
  // UTILITÁRIOS DE SEGURANÇA
  //============================================================================
  
  /// Verifica se offset está dentro dos limites seguros
  bool isSafeOffset(uint64_t Offset, uint64_t Size, uint64_t BufferSize) const;
  
  /// Verifica se tamanho está dentro dos limites seguros
  bool isSafeSize(uint64_t Size, uint64_t MaxSize) const;
  
  /// Lê valor com validação de limites
  template<typename T>
  Optional<T> readSafe(const uint8_t *Buffer, uint64_t Offset, size_t BufferSize) const {
    if (!isSafeOffset(Offset, sizeof(T), BufferSize)) {
      return None;
    }
    T Value;
    memcpy(&Value, Buffer + Offset, sizeof(T));
    return Value;
  }
  
  /// Detecta arquitetura
  uint32_t detectArchitecture(const RobustPEExtractedData &Data);
  
  //============================================================================
  // MEMBROS
  //============================================================================
  
  DiagnosticCollector Diagnostics;
  SecurityLimits SecLimits;
  bool VerboseMode = false;
  uint32_t CurrentPEOffset = 0;
};

} // namespace e2yhos
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_E2YHOS_PEEXTRACTOR_H
