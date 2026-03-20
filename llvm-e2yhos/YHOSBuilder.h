//===- YHOSBuilder.h - Construção do formato Bible YHOS ---------*- C++ -*-===//
//
// Este arquivo faz parte do conversor e2yhos para LLVM
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
/// Construtor do formato executável Bible YHOS (Your Highness Operating System)
///
/// Estrutura do arquivo YHOS:
///   +------------------+
///   | YHOS Header      | - Magic, arquitetura, offsets das tabelas
///   +------------------+
///   | Segment Table    | - __bios, __boot, __mem, __usr, __data, __kern
///   +------------------+
///   | Signature Table  | - Assinaturas (opcional)
///   +------------------+
///   | Section Table    | - .kern, .usr, .dat, .import, .export, etc
///   +------------------+
///   | Segment Data     | - Dados brutos dos segmentos
///   +------------------+
///   | Section Data     | - Dados brutos das seções
///   +------------------+
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_E2YHOS_YHOSBUILDER_H
#define LLVM_TOOLS_LLVM_E2YHOS_YHOSBUILDER_H

#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Error.h"
#include <cstdint>
#include <vector>
#include <map>
#include <set>

namespace llvm {
namespace e2yhos {

//==============================================================================
// CONSTANTES YHOS
//==============================================================================

#define YHOS_MAGIC "YHOS"
#define YHOS_VERSION 1

// Arquiteturas suportadas
#define YHOS_ARCH_X86_32     1
#define YHOS_ARCH_X86_64     2
#define YHOS_ARCH_ARM_32     3
#define YHOS_ARCH_ARM_64     4
#define YHOS_ARCH_RISCV_32   5
#define YHOS_ARCH_RISCV_64   6

// Permissões de segmento
#define YHOS_SEG_READ    (1 << 0)
#define YHOS_SEG_WRITE   (1 << 1)
#define YHOS_SEG_EXEC    (1 << 2)

// Flags de seção
#define YHOS_SECT_DAEMON     (1 << 0)  // .daemon
#define YHOS_SECT_KIO        (1 << 1)  // .kio (Kernel I/O)
#define YHOS_SECT_USER       (1 << 2)  // .usr
#define YHOS_SECT_GUI        (1 << 3)  // .gui=GUI
#define YHOS_SECT_CLT        (1 << 4)  // .gui=CLT
#define YHOS_SECT_NUI        (1 << 5)  // .gui=None
#define YHOS_SECT_DSASM      (1 << 6)  // .dsasm
#define YHOS_SECT_REF_ALOC   (1 << 7)  // .ref_aloc
#define YHOS_SECT_BOOT       (1 << 8)  // .boot
#define YHOS_SECT_BIOS       (1 << 9)  // .bios
#define YHOS_SECT_INIT       (1 << 10) // .init

// Tipos de seção
#define YHOS_SECT_CODE       1
#define YHOS_SECT_DATA       2
#define YHOS_SECT_RODATA     3
#define YHOS_SECT_BSS        4
#define YHOS_SECT_IMPORT     5
#define YHOS_SECT_EXPORT     6
#define YHOS_SECT_RESOURCE   7
#define YHOS_SECT_SYMBOL     8
#define YHOS_SECT_BOOTSIGN   9
#define YHOS_SECT_KM         10  // Kernel Module
#define YHOS_SECT_DLIB       11  // Dynamic Library
#define YHOS_SECT_DAEMON     12  // .daemon
#define YHOS_SECT_KIO        13  // .kio
#define YHOS_SECT_NULLDAT    14  // .nulldat
#define YHOS_SECT_SYMMEM     15  // .symmem

// Tipos de assinatura
#define YHOS_SIGN_BOOTLOADER 1
#define YHOS_SIGN_CODE       2
#define YHOS_SIGN_HASH       3

//==============================================================================
// ESTRUTURAS YHOS
//==============================================================================

#pragma pack(push, 1)

/// Cabeçalho principal do YHOS
struct YHOSHeader {
  char Magic[4];                    // "YHOS"
  uint32_t Version;                 // Versão do formato (1)
  uint32_t Arch;                    // Arquitetura (YHOS_ARCH_*)
  uint64_t SegmentTableOffset;      // Offset da tabela de segmentos
  uint64_t SignatureTableOffset;    // Offset da tabela de assinaturas
  uint64_t SectionTableOffset;      // Offset da tabela de seções
  uint32_t SegmentCount;            // Número de segmentos
  uint32_t SignatureCount;          // Número de assinaturas
  uint32_t SectionCount;            // Número de seções
  uint32_t Flags;                   // Flags gerais (GUI/CLT/NUI)
  uint64_t EntryPoint;              // Ponto de entrada
  uint64_t StackSize;               // Tamanho da pilha
  uint64_t HeapSize;                // Tamanho do heap
  uint32_t LinkerVersion;           // Versão do linker
  uint32_t Reserved[3];             // Reservado para uso futuro
};

/// Segmento YHOS
struct YHOSSegment {
  char Name[16];                    // Nome do segmento (__bios, __boot, etc)
  uint64_t VirtualAddress;          // Endereço virtual de carga
  uint64_t PhysicalSize;            // Tamanho no arquivo
  uint64_t MemorySize;              // Tamanho na memória (com BSS)
  uint64_t Offset;                  // Offset no arquivo
  uint32_t Permissions;             // SEG_READ, SEG_WRITE, SEG_EXEC
  uint32_t Flags;                   // Flags adicionais do segmento
  uint64_t Alignment;               // Alinhamento do segmento
  uint64_t Reserved[2];             // Reservado
};

/// Seção YHOS
struct YHOSSection {
  char Name[32];                    // Nome da seção (.kern, .usr, .dat, etc)
  uint64_t Offset;                  // Offset no arquivo
  uint64_t Size;                    // Tamanho da seção
  uint64_t VirtualAddress;          // Endereço virtual (opcional)
  uint32_t Type;                    // Tipo da seção (SECT_*)
  uint32_t Flags;                   // Flags da seção (SECT_FLAG_*)
  uint32_t Permissions;             // Permissões (SEG_READ, etc)
  uint32_t Link;                    // Índice da seção linkada (para .import/.export)
  uint32_t Info;                    // Informações adicionais
  uint64_t Alignment;               // Alinhamento
  uint64_t Reserved[2];             // Reservado
};

/// Assinatura YHOS
struct YHOSSignature {
  char Name[32];                    // Nome da assinatura
  uint32_t Type;                    // Tipo da assinatura (SIGN_*)
  uint32_t Size;                    // Tamanho dos dados
  uint64_t Offset;                  // Offset dos dados
  uint32_t HashType;                // Tipo de hash (se aplicável)
  uint32_t Reserved[3];             // Reservado
};

#pragma pack(pop)

//==============================================================================
// ESTRUTURAS DE CONSTRUÇÃO
//==============================================================================

/// Informações de segmento para construção
struct YHOSSegmentInfo {
  std::string Name;                 // __bios, __boot, __mem, __usr, __data, __kern
  uint64_t VirtualAddress;          // Endereço virtual (0 = automático)
  uint64_t PhysicalSize;            // Tamanho no arquivo
  uint64_t MemorySize;              // Tamanho na memória
  uint32_t Permissions;             // Permissões
  uint32_t Flags;                   // Flags adicionais
  uint64_t Alignment;               // Alinhamento (0 = padrão)
  
  // Dados
  std::vector<uint8_t> Data;
  
  // Seções pertencentes a este segmento
  std::vector<uint32_t> SectionIndices;
  
  YHOSSegmentInfo() : VirtualAddress(0), PhysicalSize(0), MemorySize(0),
                      Permissions(0), Flags(0), Alignment(4096) {}
};

/// Informações de seção para construção
struct YHOSSectionInfo {
  std::string Name;                 // Nome da seção
  uint32_t Type;                    // Tipo (SECT_CODE, SECT_DATA, etc)
  uint32_t Flags;                   // Flags (DAEMON, KIO, USER, GUI, etc)
  uint32_t Permissions;             // Permissões
  uint32_t Link;                    // Índice da seção linkada
  uint32_t Info;                    // Informações adicionais
  uint64_t VirtualAddress;          // Endereço virtual (0 = automático)
  uint64_t Alignment;               // Alinhamento (0 = padrão)
  
  // Dados
  std::vector<uint8_t> Data;
  
  // Para .import: lista de bibliotecas com tipo
  struct ImportEntry {
    std::string LibraryName;
    char Type;                      // 'K' = .km (Kernel Module), 'D' = .dlib (Dynamic Library)
  };
  std::vector<ImportEntry> Imports;
  
  // Para .export: lista de símbolos exportados
  std::vector<std::string> Exports;
  
  // Para .bootsign: assinatura do bootloader
  std::string BootSignature;
  
  // Para .symmem: tabela de símbolos e strings
  struct SymbolEntry {
    std::string Name;
    uint64_t Value;
    uint32_t Size;
    uint8_t Type;                   // STT_FUNC, STT_OBJECT, etc
    uint8_t Bind;                   // STB_GLOBAL, STB_LOCAL, etc
    uint16_t SectionIndex;
  };
  std::vector<SymbolEntry> Symbols;
  std::vector<uint8_t> StringTable;
  
  YHOSSectionInfo() : Type(0), Flags(0), Permissions(0), Link(0), Info(0),
                      VirtualAddress(0), Alignment(0) {}
};

/// Informações de assinatura para construção
struct YHOSSignatureInfo {
  std::string Name;
  uint32_t Type;
  std::vector<uint8_t> Data;
  uint32_t HashType;
  
  YHOSSignatureInfo() : Type(0), HashType(0) {}
};

/// Configuração completa do executável YHOS
struct YHOSBuildConfig {
  // Cabeçalho
  uint32_t Arch = YHOS_ARCH_X86_64;
  uint32_t Flags = 0;               // GUI/CLT/NUI flags
  uint64_t EntryPoint = 0;
  uint64_t StackSize = 8192;        // 8KB padrão
  uint64_t HeapSize = 65536;        // 64KB padrão
  uint32_t LinkerVersion = 1;
  
  // Segmentos
  std::vector<YHOSSegmentInfo> Segments;
  
  // Seções
  std::vector<YHOSSectionInfo> Sections;
  
  // Assinaturas
  std::vector<YHOSSignatureInfo> Signatures;
  
  // Configurações adicionais
  bool GenerateDefaultSegments = true;
  uint64_t BaseAddress = 0x1000000;  // 16MB base
  uint64_t SegmentAlignment = 4096;   // 4KB alinhamento
  uint64_t SectionAlignment = 16;     // 16 bytes alinhamento
  
  // Validação
  bool Validate = true;
  bool Verbose = false;
};

//==============================================================================
// CLASSE PRINCIPAL - YHOS BUILDER
//==============================================================================

class YHOSBuilder {
public:
  YHOSBuilder();
  ~YHOSBuilder();
  
  /// Constrói arquivo YHOS a partir dos dados extraídos
  /// \param Config - Configuração do executável YHOS
  /// \param OutputPath - Caminho do arquivo de saída
  /// \returns Error::success() se bem-sucedido
  Error build(const YHOSBuildConfig &Config, StringRef OutputPath);
  
  /// Constrói configuração padrão a partir dos dados extraídos
  /// \param CodeBuffer - Buffer com código
  /// \param DataBuffer - Buffer com dados inicializados
  /// \param RodataBuffer - Buffer com dados somente leitura
  /// \param BssSize - Tamanho do BSS
  /// \param EntryPoint - Ponto de entrada
  /// \param Arch - Arquitetura
  /// \param Flags - Flags (GUI/CLT/NUI)
  /// \param Imports - Bibliotecas importadas
  /// \param Exports - Símbolos exportados
  /// \param BootSignature - Assinatura do bootloader (opcional)
  /// \param IsKernel - É kernel?
  /// \param IsDaemon - É daemon?
  /// \returns Configuração YHOS
  YHOSBuildConfig createDefaultConfig(
      const std::vector<uint8_t> &CodeBuffer,
      const std::vector<uint8_t> &DataBuffer,
      const std::vector<uint8_t> &RodataBuffer,
      size_t BssSize,
      uint64_t EntryPoint,
      uint32_t Arch,
      uint32_t Flags,
      const std::vector<std::string> &Imports,
      const std::vector<std::string> &Exports,
      const std::string &BootSignature = "",
      bool IsKernel = false,
      bool IsDaemon = false);
  
  /// Adiciona segmento padrão
  void addDefaultSegments(YHOSBuildConfig &Config, bool IsKernel, bool IsDaemon,
                          bool IsUser);
  
  /// Adiciona seções padrão
  void addDefaultSections(YHOSBuildConfig &Config,
                          const std::vector<uint8_t> &CodeBuffer,
                          const std::vector<uint8_t> &DataBuffer,
                          const std::vector<uint8_t> &RodataBuffer,
                          size_t BssSize,
                          bool IsKernel,
                          bool IsDaemon,
                          bool IsUser,
                          const std::vector<std::string> &Imports,
                          const std::vector<std::string> &Exports,
                          const std::string &BootSignature);
  
  /// Configura permissões baseado no tipo de seção
  uint32_t getDefaultPermissionsForSection(const std::string &Name, uint32_t Type);
  
  /// Configura flags baseado no tipo de seção
  uint32_t getDefaultFlagsForSection(const std::string &Name, uint32_t Type);
  
  /// Mapeia arquitetura para string
  static std::string getArchName(uint32_t Arch);
  
  /// Obtém arquitetura a partir do nome
  static uint32_t getArchFromName(const std::string &Name);
  
  /// Calcula checksum do arquivo YHOS
  uint32_t computeChecksum(const uint8_t *Buffer, size_t Size);
  
private:
  /// Escreve cabeçalho YHOS
  Error writeHeader(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                    uint64_t SegmentTableOffset, uint64_t SignatureTableOffset,
                    uint64_t SectionTableOffset);
  
  /// Escreve tabela de segmentos
  Error writeSegmentTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                          uint64_t &CurrentOffset);
  
  /// Escreve tabela de assinaturas
  Error writeSignatureTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                            uint64_t &CurrentOffset);
  
  /// Escreve tabela de seções
  Error writeSectionTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                          uint64_t &CurrentOffset);
  
  /// Escreve dados dos segmentos
  Error writeSegmentData(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                         uint64_t &CurrentOffset);
  
  /// Escreve dados das seções
  Error writeSectionData(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                         uint64_t &CurrentOffset);
  
  /// Valida configuração
  Error validateConfig(const YHOSBuildConfig &Config);
  
  /// Alinha offset
  uint64_t alignOffset(uint64_t Offset, uint64_t Alignment);
  
  /// Converte permissões para string (debug)
  std::string permissionsToString(uint32_t Permissions);
  
  /// Converte flags para string (debug)
  std::string flagsToString(uint32_t Flags);
  
  // Membros
  bool VerboseMode = false;
};

} // namespace e2yhos
} // namespace llvm

#endif // LLVM_TOOLS_LLVM_E2YHOS_YHOSBUILDER_H
