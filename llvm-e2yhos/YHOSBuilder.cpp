//===- YHOSBuilder.cpp - Implementação do construtor Bible YHOS ----------===//
//
// Este arquivo faz parte do conversor e2yhos para LLVM
//
//===----------------------------------------------------------------------===//

#include "YHOSBuilder.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

using namespace llvm;
using namespace llvm::e2yhos;
using namespace llvm::support::endian;

//==============================================================================
// CONSTRUTOR E DESTRUTOR
//==============================================================================

YHOSBuilder::YHOSBuilder() = default;
YHOSBuilder::~YHOSBuilder() = default;

//==============================================================================
// MÉTODOS PÚBLICOS
//==============================================================================

Error YHOSBuilder::build(const YHOSBuildConfig &Config, StringRef OutputPath) {
  VerboseMode = Config.Verbose;
  
  if (VerboseMode) {
    outs() << "YHOSBuilder: Iniciando construção\n";
    outs() << "  Arquitetura: " << getArchName(Config.Arch) << "\n";
    outs() << "  Entry point: 0x" << Twine::utohexstr(Config.EntryPoint) << "\n";
    outs() << "  Stack size: " << Config.StackSize << "\n";
    outs() << "  Heap size: " << Config.HeapSize << "\n";
    outs() << "  Segmentos: " << Config.Segments.size() << "\n";
    outs() << "  Seções: " << Config.Sections.size() << "\n";
    outs() << "  Assinaturas: " << Config.Signatures.size() << "\n";
  }
  
  // Validar configuração
  if (Config.Validate) {
    if (auto Err = validateConfig(Config)) {
      return Err;
    }
  }
  
  // Abrir arquivo de saída
  std::error_code EC;
  raw_fd_ostream OS(OutputPath, EC, sys::fs::OF_None);
  if (EC) {
    return make_error<StringError>("Erro ao criar arquivo: " + EC.message(),
                                   inconvertibleErrorCode());
  }
  
  // Calcular offsets iniciais
  uint64_t CurrentOffset = sizeof(YHOSHeader);
  
  // Tabela de segmentos
  uint64_t SegmentTableOffset = CurrentOffset;
  CurrentOffset += Config.Segments.size() * sizeof(YHOSSegment);
  
  // Tabela de assinaturas
  uint64_t SignatureTableOffset = CurrentOffset;
  CurrentOffset += Config.Signatures.size() * sizeof(YHOSSignature);
  
  // Tabela de seções
  uint64_t SectionTableOffset = CurrentOffset;
  CurrentOffset += Config.Sections.size() * sizeof(YHOSSection);
  
  // Alinhar para dados
  CurrentOffset = alignOffset(CurrentOffset, 16);
  
  // Escrever cabeçalho
  if (auto Err = writeHeader(OS, Config, SegmentTableOffset,
                              SignatureTableOffset, SectionTableOffset)) {
    return Err;
  }
  
  // Escrever tabelas
  if (auto Err = writeSegmentTable(OS, Config, CurrentOffset)) {
    return Err;
  }
  
  if (auto Err = writeSignatureTable(OS, Config, CurrentOffset)) {
    return Err;
  }
  
  if (auto Err = writeSectionTable(OS, Config, CurrentOffset)) {
    return Err;
  }
  
  // Escrever dados
  if (auto Err = writeSegmentData(OS, Config, CurrentOffset)) {
    return Err;
  }
  
  if (auto Err = writeSectionData(OS, Config, CurrentOffset)) {
    return Err;
  }
  
  OS.close();
  
  if (VerboseMode) {
    outs() << "YHOSBuilder: Construção concluída!\n";
    outs() << "  Tamanho total: " << CurrentOffset << " bytes\n";
  }
  
  return Error::success();
}

YHOSBuildConfig YHOSBuilder::createDefaultConfig(
    const std::vector<uint8_t> &CodeBuffer,
    const std::vector<uint8_t> &DataBuffer,
    const std::vector<uint8_t> &RodataBuffer,
    size_t BssSize,
    uint64_t EntryPoint,
    uint32_t Arch,
    uint32_t Flags,
    const std::vector<std::string> &Imports,
    const std::vector<std::string> &Exports,
    const std::string &BootSignature,
    bool IsKernel,
    bool IsDaemon) {
  
  YHOSBuildConfig Config;
  
  Config.Arch = Arch;
  Config.Flags = Flags;
  Config.EntryPoint = EntryPoint;
  Config.StackSize = 8192;
  Config.HeapSize = 65536;
  Config.LinkerVersion = 1;
  
  // Adicionar segmentos padrão
  addDefaultSegments(Config, IsKernel, IsDaemon, !IsKernel && !IsDaemon);
  
  // Adicionar seções padrão
  addDefaultSections(Config, CodeBuffer, DataBuffer, RodataBuffer, BssSize,
                     IsKernel, IsDaemon, !IsKernel && !IsDaemon,
                     Imports, Exports, BootSignature);
  
  return Config;
}

//==============================================================================
// ADIÇÃO DE SEGMENTOS PADRÃO
//==============================================================================

void YHOSBuilder::addDefaultSegments(YHOSBuildConfig &Config, bool IsKernel,
                                       bool IsDaemon, bool IsUser) {
  uint64_t CurrentAddress = Config.BaseAddress;
  
  // Segmento __kern (código do kernel)
  if (IsKernel || IsDaemon) {
    YHOSSegmentInfo KernSeg;
    KernSeg.Name = "__kern";
    KernSeg.VirtualAddress = CurrentAddress;
    KernSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_EXEC;
    KernSeg.Alignment = 4096;
    Config.Segments.push_back(KernSeg);
    CurrentAddress += 0x1000000; // 16MB para kernel
  }
  
  // Segmento __usr (código de usuário)
  if (IsUser) {
    YHOSSegmentInfo UsrSeg;
    UsrSeg.Name = "__usr";
    UsrSeg.VirtualAddress = CurrentAddress;
    UsrSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_EXEC;
    UsrSeg.Alignment = 4096;
    Config.Segments.push_back(UsrSeg);
    CurrentAddress += 0x1000000; // 16MB para usuário
  }
  
  // Segmento __data (dados)
  YHOSSegmentInfo DataSeg;
  DataSeg.Name = "__data";
  DataSeg.VirtualAddress = CurrentAddress;
  DataSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_WRITE;
  DataSeg.Alignment = 4096;
  Config.Segments.push_back(DataSeg);
  CurrentAddress += 0x2000000; // 32MB para dados
  
  // Segmento __mem (heap/BSS)
  YHOSSegmentInfo MemSeg;
  MemSeg.Name = "__mem";
  MemSeg.VirtualAddress = CurrentAddress;
  MemSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_WRITE;
  MemSeg.Alignment = 4096;
  Config.Segments.push_back(MemSeg);
  CurrentAddress += 0x1000000; // 16MB para heap
  
  // Segmento __boot (bootloader)
  YHOSSegmentInfo BootSeg;
  BootSeg.Name = "__boot";
  BootSeg.VirtualAddress = 0x100000; // 1MB
  BootSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_EXEC;
  BootSeg.Alignment = 512; // Alinhamento de setor
  Config.Segments.push_back(BootSeg);
  
  // Segmento __bios (BIOS)
  YHOSSegmentInfo BiosSeg;
  BiosSeg.Name = "__bios";
  BiosSeg.VirtualAddress = 0xFFFF0000; // Memória alta
  BiosSeg.Permissions = YHOS_SEG_READ | YHOS_SEG_EXEC;
  BiosSeg.Alignment = 4096;
  Config.Segments.push_back(BiosSeg);
}

//==============================================================================
// ADIÇÃO DE SEÇÕES PADRÃO
//==============================================================================

void YHOSBuilder::addDefaultSections(YHOSBuildConfig &Config,
                                       const std::vector<uint8_t> &CodeBuffer,
                                       const std::vector<uint8_t> &DataBuffer,
                                       const std::vector<uint8_t> &RodataBuffer,
                                       size_t BssSize,
                                       bool IsKernel,
                                       bool IsDaemon,
                                       bool IsUser,
                                       const std::vector<std::string> &Imports,
                                       const std::vector<std::string> &Exports,
                                       const std::string &BootSignature) {
  
  // Seção .kern (código do kernel)
  if (IsKernel || IsDaemon) {
    YHOSSectionInfo KernSect;
    KernSect.Name = ".kern";
    KernSect.Type = YHOS_SECT_CODE;
    KernSect.Flags = getDefaultFlagsForSection(".kern", YHOS_SECT_CODE);
    KernSect.Permissions = getDefaultPermissionsForSection(".kern", YHOS_SECT_CODE);
    KernSect.Data = CodeBuffer;
    KernSect.Alignment = 16;
    
    // Se for daemon, adicionar flag .daemon
    if (IsDaemon) {
      KernSect.Flags |= YHOS_SECT_DAEMON;
    }
    
    // Se for kernel, adicionar flag .kio
    if (IsKernel) {
      KernSect.Flags |= YHOS_SECT_KIO;
    }
    
    Config.Sections.push_back(KernSect);
  }
  
  // Seção .usr (código de usuário)
  if (IsUser) {
    YHOSSectionInfo UsrSect;
    UsrSect.Name = ".usr";
    UsrSect.Type = YHOS_SECT_CODE;
    UsrSect.Flags = getDefaultFlagsForSection(".usr", YHOS_SECT_CODE) | YHOS_SECT_USER;
    UsrSect.Permissions = getDefaultPermissionsForSection(".usr", YHOS_SECT_CODE);
    UsrSect.Data = CodeBuffer;
    UsrSect.Alignment = 16;
    Config.Sections.push_back(UsrSect);
  }
  
  // Seção .dat (dados inicializados)
  if (!DataBuffer.empty()) {
    YHOSSectionInfo DataSect;
    DataSect.Name = ".dat";
    DataSect.Type = YHOS_SECT_DATA;
    DataSect.Flags = getDefaultFlagsForSection(".dat", YHOS_SECT_DATA);
    DataSect.Permissions = getDefaultPermissionsForSection(".dat", YHOS_SECT_DATA);
    DataSect.Data = DataBuffer;
    DataSect.Alignment = 16;
    Config.Sections.push_back(DataSect);
  }
  
  // Seção .cstring.readata (dados somente leitura)
  if (!RodataBuffer.empty()) {
    YHOSSectionInfo RodataSect;
    RodataSect.Name = ".cstring.readata";
    RodataSect.Type = YHOS_SECT_RODATA;
    RodataSect.Flags = getDefaultFlagsForSection(".cstring.readata", YHOS_SECT_RODATA);
    RodataSect.Permissions = getDefaultPermissionsForSection(".cstring.readata", YHOS_SECT_RODATA);
    RodataSect.Data = RodataBuffer;
    RodataSect.Alignment = 16;
    Config.Sections.push_back(RodataSect);
  }
  
  // Seção .nulldat (BSS - dados não inicializados)
  if (BssSize > 0) {
    YHOSSectionInfo BssSect;
    BssSect.Name = ".nulldat";
    BssSect.Type = YHOS_SECT_BSS;
    BssSect.Flags = getDefaultFlagsForSection(".nulldat", YHOS_SECT_BSS);
    BssSect.Permissions = getDefaultPermissionsForSection(".nulldat", YHOS_SECT_BSS);
    BssSect.Size = BssSize;
    BssSect.Alignment = 16;
    Config.Sections.push_back(BssSect);
  }
  
  // Seção .import (bibliotecas importadas)
  if (!Imports.empty()) {
    YHOSSectionInfo ImportSect;
    ImportSect.Name = ".import";
    ImportSect.Type = YHOS_SECT_IMPORT;
    ImportSect.Flags = getDefaultFlagsForSection(".import", YHOS_SECT_IMPORT);
    ImportSect.Permissions = getDefaultPermissionsForSection(".import", YHOS_SECT_IMPORT);
    
    for (const auto &Lib : Imports) {
      YHOSSectionInfo::ImportEntry Entry;
      Entry.LibraryName = Lib;
      // Detectar tipo pela extensão
      if (Lib.find(".km") != std::string::npos || 
          Lib.find(".kernel") != std::string::npos) {
        Entry.Type = 'K'; // Kernel Module
      } else {
        Entry.Type = 'D'; // Dynamic Library
      }
      ImportSect.Imports.push_back(Entry);
    }
    
    Config.Sections.push_back(ImportSect);
  }
  
  // Seção .export (símbolos exportados)
  if (!Exports.empty()) {
    YHOSSectionInfo ExportSect;
    ExportSect.Name = ".export";
    ExportSect.Type = YHOS_SECT_EXPORT;
    ExportSect.Flags = getDefaultFlagsForSection(".export", YHOS_SECT_EXPORT);
    ExportSect.Permissions = getDefaultPermissionsForSection(".export", YHOS_SECT_EXPORT);
    ExportSect.Exports = Exports;
    Config.Sections.push_back(ExportSect);
  }
  
  // Seção .bootsign (assinatura do bootloader)
  if (!BootSignature.empty()) {
    YHOSSectionInfo BootSect;
    BootSect.Name = "." + BootSignature;
    BootSect.Type = YHOS_SECT_BOOTSIGN;
    BootSect.Flags = getDefaultFlagsForSection(BootSect.Name, YHOS_SECT_BOOTSIGN);
    BootSect.Permissions = getDefaultPermissionsForSection(BootSect.Name, YHOS_SECT_BOOTSIGN);
    BootSect.BootSignature = BootSignature;
    Config.Sections.push_back(BootSect);
  }
  
  // Seção ._data.resource.nexec (recursos)
  YHOSSectionInfo ResourceSect;
  ResourceSect.Name = "._data.resource.nexec";
  ResourceSect.Type = YHOS_SECT_RESOURCE;
  ResourceSect.Flags = getDefaultFlagsForSection("._data.resource.nexec", YHOS_SECT_RESOURCE);
  ResourceSect.Permissions = getDefaultPermissionsForSection("._data.resource.nexec", YHOS_SECT_RESOURCE);
  ResourceSect.Size = 512; // 512 bytes para recursos
  Config.Sections.push_back(ResourceSect);
  
  // Seção .symmem (tabela de símbolos)
  // Será preenchida se houver símbolos disponíveis
  // (implementação posterior)
}

//==============================================================================
// PERMISSÕES E FLAGS PADRÃO
//==============================================================================

uint32_t YHOSBuilder::getDefaultPermissionsForSection(const std::string &Name, uint32_t Type) {
  if (Name == ".kern" || Name == ".usr" || Name == ".init" || Name == ".boot" || Name == ".bios") {
    return YHOS_SEG_READ | YHOS_SEG_EXEC;
  } else if (Name == ".dat" || Name == ".nulldat" || Name == ".data_mem") {
    return YHOS_SEG_READ | YHOS_SEG_WRITE;
  } else if (Name == ".cstring.readata" || Name == ".rodata") {
    return YHOS_SEG_READ;
  } else if (Name == ".import" || Name == ".export" || Name == ".symmem") {
    return YHOS_SEG_READ;
  } else if (Name == "._data.resource.nexec") {
    return YHOS_SEG_READ;
  }
  
  // Padrão: somente leitura
  return YHOS_SEG_READ;
}

uint32_t YHOSBuilder::getDefaultFlagsForSection(const std::string &Name, uint32_t Type) {
  uint32_t Flags = 0;
  
  if (Name.find(".daemon") != std::string::npos || Name == ".daemon") {
    Flags |= YHOS_SECT_DAEMON;
  }
  
  if (Name.find(".kio") != std::string::npos || Name == ".kio") {
    Flags |= YHOS_SECT_KIO;
  }
  
  if (Name.find(".usr") != std::string::npos || Name == ".usr") {
    Flags |= YHOS_SECT_USER;
  }
  
  if (Name.find(".gui") != std::string::npos) {
    Flags |= YHOS_SECT_GUI;
  }
  
  if (Name.find(".clt") != std::string::npos) {
    Flags |= YHOS_SECT_CLT;
  }
  
  if (Name.find(".nui") != std::string::npos) {
    Flags |= YHOS_SECT_NUI;
  }
  
  if (Name.find(".dsasm") != std::string::npos) {
    Flags |= YHOS_SECT_DSASM;
  }
  
  if (Name.find(".ref_aloc") != std::string::npos) {
    Flags |= YHOS_SECT_REF_ALOC;
  }
  
  if (Name.find(".boot") != std::string::npos) {
    Flags |= YHOS_SECT_BOOT;
  }
  
  if (Name.find(".bios") != std::string::npos) {
    Flags |= YHOS_SECT_BIOS;
  }
  
  if (Name.find(".init") != std::string::npos) {
    Flags |= YHOS_SECT_INIT;
  }
  
  return Flags;
}

//==============================================================================
// ESCRITA DO CABEÇALHO
//==============================================================================

Error YHOSBuilder::writeHeader(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                uint64_t SegmentTableOffset, uint64_t SignatureTableOffset,
                                uint64_t SectionTableOffset) {
  YHOSHeader Header;
  
  memcpy(Header.Magic, YHOS_MAGIC, 4);
  Header.Version = YHOS_VERSION;
  Header.Arch = Config.Arch;
  Header.SegmentTableOffset = SegmentTableOffset;
  Header.SignatureTableOffset = SignatureTableOffset;
  Header.SectionTableOffset = SectionTableOffset;
  Header.SegmentCount = Config.Segments.size();
  Header.SignatureCount = Config.Signatures.size();
  Header.SectionCount = Config.Sections.size();
  Header.Flags = Config.Flags;
  Header.EntryPoint = Config.EntryPoint;
  Header.StackSize = Config.StackSize;
  Header.HeapSize = Config.HeapSize;
  Header.LinkerVersion = Config.LinkerVersion;
  memset(Header.Reserved, 0, sizeof(Header.Reserved));
  
  OS.write(reinterpret_cast<const char*>(&Header), sizeof(Header));
  
  if (VerboseMode) {
    outs() << "  Cabeçalho escrito: offset 0x0\n";
    outs() << "    Magic: " << std::string(Header.Magic, 4) << "\n";
    outs() << "    Version: " << Header.Version << "\n";
    outs() << "    Arch: " << getArchName(Header.Arch) << "\n";
    outs() << "    Entry: 0x" << Twine::utohexstr(Header.EntryPoint) << "\n";
  }
  
  return Error::success();
}

//==============================================================================
// ESCRITA DA TABELA DE SEGMENTOS
//==============================================================================

Error YHOSBuilder::writeSegmentTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                      uint64_t &CurrentOffset) {
  uint64_t TableStart = OS.tell();
  
  for (const auto &SegInfo : Config.Segments) {
    YHOSSegment Segment;
    
    memset(&Segment, 0, sizeof(Segment));
    strncpy(Segment.Name, SegInfo.Name.c_str(), 15);
    Segment.Name[15] = '\0';
    Segment.VirtualAddress = SegInfo.VirtualAddress;
    Segment.PhysicalSize = SegInfo.Data.size();
    Segment.MemorySize = SegInfo.MemorySize > 0 ? SegInfo.MemorySize : SegInfo.Data.size();
    Segment.Offset = CurrentOffset; // Será atualizado depois
    Segment.Permissions = SegInfo.Permissions;
    Segment.Flags = SegInfo.Flags;
    Segment.Alignment = SegInfo.Alignment;
    
    OS.write(reinterpret_cast<const char*>(&Segment), sizeof(Segment));
    
    if (VerboseMode) {
      outs() << "  Segmento: " << SegInfo.Name << "\n";
      outs() << "    VA: 0x" << Twine::utohexstr(Segment.VirtualAddress) << "\n";
      outs() << "    Size: " << Segment.PhysicalSize << "\n";
      outs() << "    Perm: " << permissionsToString(Segment.Permissions) << "\n";
    }
  }
  
  if (VerboseMode) {
    outs() << "  Tabela de segmentos escrita: offset 0x" 
           << Twine::utohexstr(TableStart) << "\n";
  }
  
  return Error::success();
}

//==============================================================================
// ESCRITA DA TABELA DE ASSINATURAS
//==============================================================================

Error YHOSBuilder::writeSignatureTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                        uint64_t &CurrentOffset) {
  uint64_t TableStart = OS.tell();
  
  for (const auto &SigInfo : Config.Signatures) {
    YHOSSignature Signature;
    
    memset(&Signature, 0, sizeof(Signature));
    strncpy(Signature.Name, SigInfo.Name.c_str(), 31);
    Signature.Name[31] = '\0';
    Signature.Type = SigInfo.Type;
    Signature.Size = SigInfo.Data.size();
    Signature.Offset = CurrentOffset;
    Signature.HashType = SigInfo.HashType;
    
    OS.write(reinterpret_cast<const char*>(&Signature), sizeof(Signature));
    
    // Escrever dados da assinatura
    if (!SigInfo.Data.empty()) {
      OS.write(reinterpret_cast<const char*>(SigInfo.Data.data()), SigInfo.Data.size());
      CurrentOffset += SigInfo.Data.size();
      CurrentOffset = alignOffset(CurrentOffset, 16);
      OS.seek(CurrentOffset);
    }
    
    if (VerboseMode) {
      outs() << "  Assinatura: " << SigInfo.Name << "\n";
      outs() << "    Type: " << SigInfo.Type << "\n";
      outs() << "    Size: " << SigInfo.Data.size() << "\n";
    }
  }
  
  if (VerboseMode) {
    outs() << "  Tabela de assinaturas escrita: offset 0x" 
           << Twine::utohexstr(TableStart) << "\n";
  }
  
  return Error::success();
}

//==============================================================================
// ESCRITA DA TABELA DE SEÇÕES
//==============================================================================

Error YHOSBuilder::writeSectionTable(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                      uint64_t &CurrentOffset) {
  uint64_t TableStart = OS.tell();
  
  for (const auto &SectInfo : Config.Sections) {
    YHOSSection Section;
    
    memset(&Section, 0, sizeof(Section));
    strncpy(Section.Name, SectInfo.Name.c_str(), 31);
    Section.Name[31] = '\0';
    Section.Offset = CurrentOffset;
    Section.Size = SectInfo.Data.size() > 0 ? SectInfo.Data.size() : SectInfo.Size;
    Section.VirtualAddress = SectInfo.VirtualAddress;
    Section.Type = SectInfo.Type;
    Section.Flags = SectInfo.Flags;
    Section.Permissions = SectInfo.Permissions;
    Section.Link = SectInfo.Link;
    Section.Info = SectInfo.Info;
    Section.Alignment = SectInfo.Alignment;
    
    OS.write(reinterpret_cast<const char*>(&Section), sizeof(Section));
    
    if (VerboseMode) {
      outs() << "  Seção: " << SectInfo.Name << "\n";
      outs() << "    Type: " << SectInfo.Type << "\n";
      outs() << "    Size: " << Section.Size << "\n";
      outs() << "    Flags: " << flagsToString(SectInfo.Flags) << "\n";
      outs() << "    Perm: " << permissionsToString(Section.Permissions) << "\n";
    }
  }
  
  if (VerboseMode) {
    outs() << "  Tabela de seções escrita: offset 0x" 
           << Twine::utohexstr(TableStart) << "\n";
  }
  
  return Error::success();
}

//==============================================================================
// ESCRITA DOS DADOS DOS SEGMENTOS
//==============================================================================

Error YHOSBuilder::writeSegmentData(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                     uint64_t &CurrentOffset) {
  // Atualizar offsets dos segmentos e escrever dados
  // Primeiro, precisamos reposicionar para escrever os offsets reais
  // Isso é complexo, então vamos armazenar os offsets em um vetor temporário
  
  std::vector<uint64_t> SegmentOffsets;
  uint64_t DataStart = CurrentOffset;
  
  for (const auto &SegInfo : Config.Segments) {
    SegmentOffsets.push_back(CurrentOffset);
    
    if (!SegInfo.Data.empty()) {
      OS.write(reinterpret_cast<const char*>(SegInfo.Data.data()), SegInfo.Data.size());
      CurrentOffset += SegInfo.Data.size();
      CurrentOffset = alignOffset(CurrentOffset, SegInfo.Alignment);
      OS.seek(CurrentOffset);
    }
  }
  
  // Agora, atualizar a tabela de segmentos com os offsets corretos
  uint64_t SegmentTableOffset = sizeof(YHOSHeader);
  OS.seek(SegmentTableOffset);
  
  for (size_t i = 0; i < Config.Segments.size(); i++) {
    YHOSSegment Segment;
    OS.read(reinterpret_cast<char*>(&Segment), sizeof(Segment));
    Segment.Offset = SegmentOffsets[i];
    OS.seek(SegmentTableOffset + i * sizeof(Segment));
    OS.write(reinterpret_cast<const char*>(&Segment), sizeof(Segment));
  }
  
  // Voltar para o final
  OS.seek(CurrentOffset);
  
  if (VerboseMode) {
    outs() << "  Dados dos segmentos escritos: offset 0x" 
           << Twine::utohexstr(DataStart) << "\n";
    outs() << "    Tamanho total: " << (CurrentOffset - DataStart) << " bytes\n";
  }
  
  return Error::success();
}

//==============================================================================
// ESCRITA DOS DADOS DAS SEÇÕES
//==============================================================================

Error YHOSBuilder::writeSectionData(raw_fd_ostream &OS, const YHOSBuildConfig &Config,
                                     uint64_t &CurrentOffset) {
  std::vector<uint64_t> SectionOffsets;
  uint64_t DataStart = CurrentOffset;
  
  for (const auto &SectInfo : Config.Sections) {
    SectionOffsets.push_back(CurrentOffset);
    
    // Escrever dados baseado no tipo da seção
    if (!SectInfo.Data.empty()) {
      OS.write(reinterpret_cast<const char*>(SectInfo.Data.data()), SectInfo.Data.size());
      CurrentOffset += SectInfo.Data.size();
      
    } else if (SectInfo.Type == YHOS_SECT_IMPORT && !SectInfo.Imports.empty()) {
      // Escrever tabela de importação
      for (const auto &Import : SectInfo.Imports) {
        OS.write(&Import.Type, 1);
        OS.write(Import.LibraryName.c_str(), Import.LibraryName.size() + 1);
        CurrentOffset += 1 + Import.LibraryName.size() + 1;
      }
      
    } else if (SectInfo.Type == YHOS_SECT_EXPORT && !SectInfo.Exports.empty()) {
      // Escrever tabela de exportação
      for (const auto &Export : SectInfo.Exports) {
        OS.write(Export.c_str(), Export.size() + 1);
        CurrentOffset += Export.size() + 1;
      }
      
    } else if (SectInfo.Type == YHOS_SECT_BOOTSIGN && !SectInfo.BootSignature.empty()) {
      // Escrever assinatura do bootloader
      OS.write(SectInfo.BootSignature.c_str(), SectInfo.BootSignature.size() + 1);
      CurrentOffset += SectInfo.BootSignature.size() + 1;
      
    } else if (SectInfo.Type == YHOS_SECT_RESOURCE && SectInfo.Size > 0) {
      // Escrever espaço reservado para recursos
      std::vector<uint8_t> Zeros(SectInfo.Size, 0);
      OS.write(reinterpret_cast<const char*>(Zeros.data()), SectInfo.Size);
      CurrentOffset += SectInfo.Size;
      
    } else if (SectInfo.Type == YHOS_SECT_BSS && SectInfo.Size > 0) {
      // BSS não ocupa espaço no arquivo
      // Apenas atualizar offset para manter consistência
      
    } else if (SectInfo.Type == YHOS_SECT_SYMBOL && !SectInfo.Symbols.empty()) {
      // Escrever tabela de símbolos (implementação posterior)
    }
    
    // Alinhar
    if (SectInfo.Alignment > 0) {
      CurrentOffset = alignOffset(CurrentOffset, SectInfo.Alignment);
      OS.seek(CurrentOffset);
    }
  }
  
  // Atualizar a tabela de seções com os offsets corretos
  uint64_t SectionTableOffset = sizeof(YHOSHeader) + 
                                Config.Segments.size() * sizeof(YHOSSegment) +
                                Config.Signatures.size() * sizeof(YHOSSignature);
  OS.seek(SectionTableOffset);
  
  for (size_t i = 0; i < Config.Sections.size(); i++) {
    YHOSSection Section;
    OS.read(reinterpret_cast<char*>(&Section), sizeof(Section));
    Section.Offset = SectionOffsets[i];
    OS.seek(SectionTableOffset + i * sizeof(Section));
    OS.write(reinterpret_cast<const char*>(&Section), sizeof(Section));
  }
  
  // Voltar para o final
  OS.seek(CurrentOffset);
  
  if (VerboseMode) {
    outs() << "  Dados das seções escritos: offset 0x" 
           << Twine::utohexstr(DataStart) << "\n";
    outs() << "    Tamanho total: " << (CurrentOffset - DataStart) << " bytes\n";
  }
  
  return Error::success();
}

//==============================================================================
// VALIDAÇÃO DA CONFIGURAÇÃO
//==============================================================================

Error YHOSBuilder::validateConfig(const YHOSBuildConfig &Config) {
  // Validar arquitetura
  if (Config.Arch != YHOS_ARCH_X86_32 && Config.Arch != YHOS_ARCH_X86_64 &&
      Config.Arch != YHOS_ARCH_ARM_32 && Config.Arch != YHOS_ARCH_ARM_64 &&
      Config.Arch != YHOS_ARCH_RISCV_32 && Config.Arch != YHOS_ARCH_RISCV_64) {
    return make_error<StringError>("Arquitetura inválida: " + Twine(Config.Arch).str(),
                                   inconvertibleErrorCode());
  }
  
  // Validar ponto de entrada
  if (Config.EntryPoint == 0 && Config.Arch != YHOS_ARCH_RISCV_32) {
    // Aviso, mas não erro - pode ser biblioteca
    if (VerboseMode) {
      outs() << "  Aviso: Entry point é 0 (possível biblioteca)\n";
    }
  }
  
  // Validar segmentos
  if (Config.Segments.empty()) {
    return make_error<StringError>("Nenhum segmento definido", inconvertibleErrorCode());
  }
  
  for (const auto &Seg : Config.Segments) {
    if (Seg.Name.empty()) {
      return make_error<StringError>("Segmento sem nome", inconvertibleErrorCode());
    }
    
    if (Seg.Permissions == 0) {
      return make_error<StringError>("Segmento " + Seg.Name + " sem permissões",
                                     inconvertibleErrorCode());
    }
  }
  
  // Validar seções
  for (const auto &Sect : Config.Sections) {
    if (Sect.Name.empty()) {
      return make_error<StringError>("Seção sem nome", inconvertibleErrorCode());
    }
    
    if (Sect.Type == 0) {
      return make_error<StringError>("Seção " + Sect.Name + " sem tipo",
                                     inconvertibleErrorCode());
    }
  }
  
  return Error::success();
}

//==============================================================================
// UTILITÁRIOS
//==============================================================================

uint64_t YHOSBuilder::alignOffset(uint64_t Offset, uint64_t Alignment) {
  if (Alignment == 0) return Offset;
  uint64_t Remainder = Offset % Alignment;
  if (Remainder == 0) return Offset;
  return Offset + (Alignment - Remainder);
}

std::string YHOSBuilder::permissionsToString(uint32_t Permissions) {
  std::string Result;
  if (Permissions & YHOS_SEG_READ) Result += "R";
  if (Permissions & YHOS_SEG_WRITE) Result += "W";
  if (Permissions & YHOS_SEG_EXEC) Result += "X";
  if (Result.empty()) Result = "---";
  return Result;
}

std::string YHOSBuilder::flagsToString(uint32_t Flags) {
  std::vector<std::string> FlagStrings;
  
  if (Flags & YHOS_SECT_DAEMON) FlagStrings.push_back("DAEMON");
  if (Flags & YHOS_SECT_KIO) FlagStrings.push_back("KIO");
  if (Flags & YHOS_SECT_USER) FlagStrings.push_back("USER");
  if (Flags & YHOS_SECT_GUI) FlagStrings.push_back("GUI");
  if (Flags & YHOS_SECT_CLT) FlagStrings.push_back("CLT");
  if (Flags & YHOS_SECT_NUI) FlagStrings.push_back("NUI");
  if (Flags & YHOS_SECT_DSASM) FlagStrings.push_back("DSASM");
  if (Flags & YHOS_SECT_REF_ALOC) FlagStrings.push_back("REF_ALOC");
  if (Flags & YHOS_SECT_BOOT) FlagStrings.push_back("BOOT");
  if (Flags & YHOS_SECT_BIOS) FlagStrings.push_back("BIOS");
  if (Flags & YHOS_SECT_INIT) FlagStrings.push_back("INIT");
  
  if (FlagStrings.empty()) return "NONE";
  
  std::string Result;
  for (size_t i = 0; i < FlagStrings.size(); i++) {
    if (i > 0) Result += ",";
    Result += FlagStrings[i];
  }
  return Result;
}

std::string YHOSBuilder::getArchName(uint32_t Arch) {
  switch (Arch) {
    case YHOS_ARCH_X86_32: return "x86_32";
    case YHOS_ARCH_X86_64: return "x86_64";
    case YHOS_ARCH_ARM_32: return "arm32";
    case YHOS_ARCH_ARM_64: return "arm64";
    case YHOS_ARCH_RISCV_32: return "riscv32";
    case YHOS_ARCH_RISCV_64: return "riscv64";
    default: return "unknown";
  }
}

uint32_t YHOSBuilder::getArchFromName(const std::string &Name) {
  if (Name == "x86_32") return YHOS_ARCH_X86_32;
  if (Name == "x86_64") return YHOS_ARCH_X86_64;
  if (Name == "arm32") return YHOS_ARCH_ARM_32;
  if (Name == "arm64") return YHOS_ARCH_ARM_64;
  if (Name == "riscv32") return YHOS_ARCH_RISCV_32;
  if (Name == "riscv64") return YHOS_ARCH_RISCV_64;
  return YHOS_ARCH_X86_64;
}

uint32_t YHOSBuilder::computeChecksum(const uint8_t *Buffer, size_t Size) {
  uint32_t Sum = 0;
  for (size_t i = 0; i < Size; i++) {
    Sum += Buffer[i];
    Sum = (Sum >> 16) + (Sum & 0xFFFF);
  }
  return Sum & 0xFFFF;
}
