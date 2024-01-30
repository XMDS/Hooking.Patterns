/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */

#include "Hooking.Patterns.h"

#include <unistd.h>
#include <inttypes.h> 
#include <fcntl.h>
#include <sys/mman.h>
#include <algorithm>
#include <fstream>
#include <map>
#include <utility>

#ifdef PATTERNS_USE_XDL
#include "xdl.h" // https://github.com/hexhacking/xDL
#define PATTERNS_DL_OPEN(name, flags) xdl_open(name, XDL_DEFAULT)
#define PATTERNS_DL_ADDR(addr, vname) xdl_info_t vname; \
void* cache = nullptr; \
xdl_addr(reinterpret_cast<void*>(addr), &vname, &cache)
#define PATTERNS_DL_ADDR_CLEAN xdl_addr_clean(&cache)
#define PATTERNS_DL_ITERATE_PHDR(callback, data) xdl_iterate_phdr(callback, data, XDL_DEFAULT | XDL_FULL_PATHNAME)
#else
#include <dlfcn.h>
#include <link.h>
#define PATTERNS_DL_OPEN(name, flags) dlopen(name, flags)
#define PATTERNS_DL_ADDR(addr, vname) Dl_info vname; \
dladdr(reinterpret_cast<void*>(addr), &vname)
#define PATTERNS_DL_ADDR_CLEAN
#define PATTERNS_DL_ITERATE_PHDR(callback, data) dl_iterate_phdr(callback, data)
#if __ANDROID_API__ < 21
#error dl_iterate_phdr is not supported on this platform (android 4.4). Please use xDL. Enable PATTERNS_USE_XDL.
#endif
#endif // PATTERNS_USE_XDL

 // The Android logging library may potentially cause some performance overhead and affect the execution speed of the code. 
 // However, it is recommended to enable it. If you don't need it, disable it.
#ifdef PATTERNS_ANDROID_LOGGING
#include <android/log.h>
#define PATTERNS_NAME "Hooking.Patterns"
#define PATTERNS_LOGI(text) ((void)__android_log_write(ANDROID_LOG_INFO, PATTERNS_NAME, text))
#define PATTERNS_LOGE(text) ((void)__android_log_write(ANDROID_LOG_ERROR, PATTERNS_NAME, text))
#define PATTERNS_LOGW(text) ((void)__android_log_write(ANDROID_LOG_WARN, PATTERNS_NAME, text))
#define PATTERNS_LOGIS(text, ...) ((void)__android_log_print(ANDROID_LOG_INFO, PATTERNS_NAME, text, __VA_ARGS__))
#define PATTERNS_LOGES(text, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, PATTERNS_NAME, text, __VA_ARGS__))
#define PATTERNS_LOGWS(text, ...) ((void)__android_log_print(ANDROID_LOG_WARN, PATTERNS_NAME, text, __VA_ARGS__))
#else
#define PATTERNS_LOGE(text) ((void)0)
#define PATTERNS_LOGES(...) ((void)0)
#define PATTERNS_LOGI(text) ((void)0)
#define PATTERNS_LOGIS(...) ((void)0)
#define PATTERNS_LOGW(text) ((void)0)
#define PATTERNS_LOGWS(...) ((void)0)
#endif

#ifndef __LP64__
typedef Elf32_Ehdr Elf_ehdr;
typedef elf32_phdr elf_phdr;
typedef elf32_shdr elf_shdr;
#define PATTERNS_ADDR_FMT "0x%" PRIx32
#else
typedef Elf64_Ehdr Elf_ehdr;
typedef elf64_phdr elf_phdr;
typedef elf64_shdr elf_shdr;
#define PATTERNS_ADDR_FMT "0x%" PRIx64 // warning
#endif // 


#if PATTERNS_USE_HINTS

// from boost someplace
template <std::uint64_t FnvPrime, std::uint64_t OffsetBasis>
struct basic_fnv_1
{
	std::uint64_t operator()(std::string_view text) const
	{
		std::uint64_t hash = OffsetBasis;
		for (auto it : text)
		{
			hash *= FnvPrime;
			hash ^= it;
		}

		return hash;
	}
};

static constexpr std::uint64_t fnv_prime = 1099511628211u;
static constexpr std::uint64_t fnv_offset_basis = 14695981039346656037u;

typedef basic_fnv_1<fnv_prime, fnv_offset_basis> fnv_1;

#endif

namespace hook
{

	ptrdiff_t details::get_process_base(const std::string& librarys)
	{
		if (librarys.empty())
		{
			PATTERNS_LOGE("get_process_base: librarys is empty.");
			return 0u;
		}

		ptrdiff_t base = 0u;
		std::string buffer;
		std::ifstream fp("/proc/self/maps");
		if (fp)
		{
			while (std::getline(fp, buffer))
			{
				if (buffer.find(librarys) != std::string::npos && buffer.find("00000000") != std::string::npos)
				{
					base = std::stoul(buffer, nullptr, 16);
					break;
				}
			}
			fp.close();
		}

		if (base == 0u)
		{
			uintptr_t arg[2] = { (uintptr_t)librarys.c_str(), (uintptr_t)&base };
			PATTERNS_DL_ITERATE_PHDR([](struct dl_phdr_info* info, size_t size, void* data) -> int
				{
					if (info->dlpi_phdr != nullptr)
					{
						for (int i = 0; i < info->dlpi_phnum; i++)
						{
							if (strstr(info->dlpi_name, reinterpret_cast<const char*>(reinterpret_cast<uintptr_t*>(data)[0])) 
								&& info->dlpi_phdr[i].p_type == PT_LOAD && info->dlpi_phdr[i].p_vaddr == 0u) // support for android 9.0+ arm64 elf (eg: libart.so)
							{
								*reinterpret_cast<uintptr_t**>(data)[1] = info->dlpi_addr;
								PATTERNS_LOGIS("get_process_base: dl_iterate_phdr info: lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", info->dlpi_name, (uintptr_t)info->dlpi_addr);
								return 1; // exit
							}
						}
					}
					return 0;
				}, arg);
		}

		if (base == 0u)
		{
			PATTERNS_LOGE("get_process_base: failed to get base address.");
		}
		return base;
	}

	const std::string details::get_process_name()
	{
		std::string buffer;
		std::ifstream fp("/proc/self/cmdline");
		if (fp)
		{
			std::getline(fp, buffer);
			fp.close();
		}
		return buffer;
	}

	static std::vector<std::string>& get_process_librarys()
	{
		static std::vector<std::string> librarys;
		librarys.clear();
		const std::string process_name = details::get_process_name();

		std::string buffer;
		std::ifstream fp("/proc/self/maps");
		if (fp)
		{
			while (std::getline(fp, buffer))
			{
				if (buffer.find(process_name.c_str()) != std::string::npos && buffer.find("(deleted)") == std::string::npos)
				{
					std::string library_name = buffer.substr(buffer.find_last_of('/') + 1);

					if (PATTERNS_DL_OPEN(library_name.c_str(), RTLD_NOLOAD)) // check library is loaded
					{
						if (std::find(librarys.begin(), librarys.end(), library_name) == librarys.end())
						{
							librarys.emplace_back(library_name);
							PATTERNS_LOGIS("get_process_librarys: The library '%s' has been loaded and the search was successful.", library_name.c_str());
						}
					}
				}
			}
			fp.close();
		}

		return librarys;
	}


#if PATTERNS_USE_HINTS
static auto& getHints()
{
	static std::multimap<uint64_t, uintptr_t> hints;
	return hints;
}
#endif

static void TransformPattern(std::string_view pattern, std::basic_string<uint8_t>& data, std::basic_string<uint8_t>& mask)
{
	uint8_t tempDigit = 0;
	bool tempFlag = false;

	auto tol = [] (char ch) -> uint8_t
	{
		if (ch >= 'A' && ch <= 'F') return uint8_t(ch - 'A' + 10);
		if (ch >= 'a' && ch <= 'f') return uint8_t(ch - 'a' + 10);
		return uint8_t(ch - '0');
	};

	for (auto ch : pattern)
	{
		if (ch == ' ')
		{
			continue;
		}
		else if (ch == '?')
		{
			data.push_back(0);
			mask.push_back(0);
		}
		else if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
		{
			uint8_t thisDigit = tol(ch);

			if (!tempFlag)
			{
				tempDigit = thisDigit << 4;
				tempFlag = true;
			}
			else
			{
				tempDigit |= thisDigit;
				tempFlag = false;

				data.push_back(tempDigit);
				mask.push_back(0xFF);
			}
		}
	}
}

class executable_meta
{
private:
	// key: elf head, value: file size
	std::map<Elf_ehdr*, off_t> m_elf;
	
	// file section
	// key: lib_name : section_name, value: begin : end
	// All readable sections form file
	std::map<std::pair<const std::string, const std::string>, std::pair<uintptr_t, uintptr_t>> m_sections;
	// executable setion form file, only name is .text .plt .init .init_array .fini .fini_array etc
	std::map<std::pair<const std::string, const std::string>, std::pair<uintptr_t, uintptr_t>> m_executable_sections;

	// memory segment
	// key: lib_name : id, value: begin : end
	// All readable segments form memory
	std::map<std::pair<const std::string, uint16_t>, std::pair<uintptr_t, uintptr_t>> m_segments;
	// executable segment form memory, only type is PF_R or PF_X and flags is PT_LOAD
	std::map<std::pair<const std::string, uint16_t>, std::pair<uintptr_t, uintptr_t>> m_executable_segments;
	
	// library name (path) or process_name
	std::string m_name;

	void FindLibrarys()
	{
		m_name = (m_name.empty() ? details::get_process_name() : m_name);

		PATTERNS_DL_ITERATE_PHDR([](struct dl_phdr_info* info, size_t size, void* data) -> int
			{
				executable_meta* self = reinterpret_cast<executable_meta*>(data);
				if (self->m_name.empty())
				{
					return 1; // exit
				}

				auto ExplainElfSection = [=]() -> bool
				{
					bool result = false;

					int fd = open(info->dlpi_name, O_RDONLY | O_CLOEXEC);
					if (fd == -1)
					{
						PATTERNS_LOGES("Explain elf file: open file failed: %s", info->dlpi_name);
						return result;
					}
					off_t fsize = lseek(fd, 0, SEEK_END);
					if (fsize <= 0)
					{
						PATTERNS_LOGES("Explain elf file: get file size failed: %s", info->dlpi_name);
						close(fd);
						return result;
					}
					void* fdata = mmap(nullptr, fsize, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
					close(fd);
					if (fdata == MAP_FAILED)
					{
						PATTERNS_LOGES("Explain elf file: mmap failed: %d - %s", errno, strerror(errno));
						return result;
					}
					Elf_ehdr* ehdr = reinterpret_cast<Elf_ehdr*>(fdata);
					if (ehdr->e_ident[EI_MAG0] != 0x7F || ehdr->e_ident[EI_MAG1] != 'E' || ehdr->e_ident[EI_MAG2] != 'L' || ehdr->e_ident[EI_MAG3] != 'F')
					{
						PATTERNS_LOGES("Explain elf file: this is not an ELF file: %s", info->dlpi_name);
						munmap(fdata, fsize);
						return result;
					}

					elf_shdr* shdr = reinterpret_cast<elf_shdr*>(((uintptr_t)ehdr) + ehdr->e_shoff);
					uintptr_t shdr_addr = (uintptr_t)shdr;
					char* shstrtab = reinterpret_cast<char*>((uintptr_t)ehdr + shdr[ehdr->e_shstrndx].sh_offset);

					for (int i = 0; i < ehdr->e_shnum; i++, shdr_addr += ehdr->e_shentsize)
					{
						elf_shdr* sec_info = reinterpret_cast<elf_shdr*>(shdr_addr);

						std::string name = shstrtab + sec_info->sh_name;
						if (sec_info->sh_type == SHT_PROGBITS && sec_info->sh_flags == (SHF_ALLOC | SHF_EXECINSTR))
						{
							self->m_executable_sections.emplace(std::make_pair(info->dlpi_name, name), 
								std::make_pair(info->dlpi_addr + sec_info->sh_addr, info->dlpi_addr + sec_info->sh_addr + sec_info->sh_size));
							PATTERNS_LOGIS("Explain elf file: executable section: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
							PATTERNS_LOGIS("section info: section_name: %s, section_start: " PATTERNS_ADDR_FMT ", section_end: " PATTERNS_ADDR_FMT "", name.c_str(), (uintptr_t)(info->dlpi_addr + sec_info->sh_addr), (uintptr_t)(info->dlpi_addr + sec_info->sh_addr + sec_info->sh_size));
						}
						if (sec_info->sh_addr == 0 && name.empty()) // .elf_head
						{
							name = ".elf_head";
							sec_info->sh_size = ehdr->e_ehsize;
						}
						self->m_sections.emplace(std::make_pair(info->dlpi_name, name), 
							std::make_pair(info->dlpi_addr + sec_info->sh_addr, info->dlpi_addr + sec_info->sh_addr + sec_info->sh_size));
						PATTERNS_LOGIS("Explain elf file: section: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
						PATTERNS_LOGIS("section info: section_name: %s, section_start: " PATTERNS_ADDR_FMT ", section_end: " PATTERNS_ADDR_FMT "", name.c_str(), (uintptr_t)(info->dlpi_addr + sec_info->sh_addr), (uintptr_t)(info->dlpi_addr + sec_info->sh_addr + sec_info->sh_size));
					}

					self->m_elf.emplace(ehdr, fsize);
					return true;
				};

				static const std::string process_name = details::get_process_name();
				if (self->m_name == process_name) // = process name
				{
					// lib_name: xxx.so 
					// info->dlpi_name: /.../.../xxx.so
					static std::vector<std::string> section_lib_name = get_process_librarys();
					static std::vector<std::string> segment_lib_name = section_lib_name;
					if (section_lib_name.empty() || segment_lib_name.empty())
					{
						return 1; // exit
					}

					for (auto i = section_lib_name.begin(); i != section_lib_name.end();)
					{
						if (strstr(info->dlpi_name, i->c_str()) && strstr(info->dlpi_name, process_name.c_str()))
						{
							if (ExplainElfSection())
							{
								i = section_lib_name.erase(i);
								continue; // next
							}
							PATTERNS_LOGWS("Explain Elf files failed: %s", info->dlpi_name);
						}
						++i; // next
					}

					for (auto l = segment_lib_name.begin(); l != segment_lib_name.end();)
					{
						if (strstr(info->dlpi_name, l->c_str()) && strstr(info->dlpi_name, process_name.c_str()))
						{
							if (info->dlpi_phdr != nullptr)
							{
								for (int j = 0; j < info->dlpi_phnum; j++)
								{
									if (info->dlpi_phdr[j].p_type == PT_LOAD && info->dlpi_phdr[j].p_flags == (PF_R | PF_X))
									{
										self->m_executable_segments.emplace(std::make_pair(info->dlpi_name, j), 
											std::make_pair(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr, info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
										PATTERNS_LOGIS("Explain elf file: executable segment: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", 
											self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
										PATTERNS_LOGIS("segment info: id: %d, segment_start: " PATTERNS_ADDR_FMT ", segment_end: " PATTERNS_ADDR_FMT "", 
											j, (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
									}
									self->m_segments.emplace(std::make_pair(info->dlpi_name, j), 
										std::make_pair(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr, info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
									PATTERNS_LOGIS("Explain elf file: segment: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", 
										self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
									PATTERNS_LOGIS("segment info: id: %d, segment_start: " PATTERNS_ADDR_FMT ", segment_end: " PATTERNS_ADDR_FMT "", 
										j, (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
								}
								l = segment_lib_name.erase(l);
								continue; // next
							}
						}
						++l; // next
					}
				}
				else // = library name(path)
				{
					if (strstr(info->dlpi_name, self->m_name.c_str()))
					{
						if (ExplainElfSection() || info->dlpi_phdr != nullptr)
						{
							for (int j = 0; j < info->dlpi_phnum; j++)
							{
								if (info->dlpi_phdr[j].p_type == PT_LOAD && info->dlpi_phdr[j].p_flags == (PF_R | PF_X))
								{
									self->m_executable_segments.emplace(std::make_pair(info->dlpi_name, j), 
										std::make_pair(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr, info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
									PATTERNS_LOGIS("Explain elf file: executable segment: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", 
										self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
									PATTERNS_LOGIS("segment info: id: %d, segment_start: " PATTERNS_ADDR_FMT ", segment_end: " PATTERNS_ADDR_FMT "", 
										j, (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
								}
								self->m_segments.emplace(std::make_pair(info->dlpi_name, j), 
									std::make_pair(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr, info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
								PATTERNS_LOGIS("Explain elf file: segment: process_name: %s, lib_name: %s, lib_base: " PATTERNS_ADDR_FMT "", 
									self->m_name.c_str(), info->dlpi_name, (uintptr_t)info->dlpi_addr);
								PATTERNS_LOGIS("segment info: id: %d, segment_start: " PATTERNS_ADDR_FMT ", segment_end: " PATTERNS_ADDR_FMT "", 
									j, (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr), (uintptr_t)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr + info->dlpi_phdr[j].p_memsz));
							}
							return 1; // exit
						}
						PATTERNS_LOGWS("Explain Elf files failed: %s", info->dlpi_name);
					}
				}
				return 0;
			}, this);
	}

	explicit executable_meta(const std::string& lib_name)
		: m_name(lib_name.empty() ? m_name : lib_name)
	{
	}

public:
	void Initialize(uintptr_t begin)
	{
		if (m_name.empty())
		{
			PATTERNS_DL_ADDR(begin, info);
			if (info.dli_fbase == nullptr)
			{
				return;
			}
			if (info.dli_fname != nullptr)
			{
				m_name = info.dli_fname;
			}
			PATTERNS_DL_ADDR_CLEAN;
		}
		
		FindLibrarys();

		if (!m_sections.empty())
		{
			for (auto& section : m_sections)
			{
				if (section.second.first <= begin && begin < section.second.second)
				{
					uintptr_t end = section.second.second;
					std::pair<const std::string, const std::string> name = section.first;
					m_sections.clear();
					m_sections.emplace(name, std::make_pair(begin, end));
					m_executable_sections.clear();
					m_executable_sections.emplace(name, std::make_pair(begin, end));

					PATTERNS_LOGIS("executable_meta::Initialize: lib_name: %s, section_name: %s, begin: " PATTERNS_ADDR_FMT ", end: " PATTERNS_ADDR_FMT "", 
						name.first.c_str(), name.second.c_str(), begin, end);
					break;
				}
			}
		}
		if (!m_segments.empty())
		{
			for (auto& segment : m_segments)
			{
				if (segment.second.first <= begin && begin < segment.second.second)
				{
					uintptr_t end = segment.second.second;
					std::pair<const std::string, uint16_t> name = segment.first;
					m_segments.clear();
					m_segments.emplace(name, std::make_pair(begin, end));
					m_executable_segments.clear();
					m_executable_segments.emplace(name, std::make_pair(begin, end));

					PATTERNS_LOGIS("executable_meta::Initialize: lib_name: %s, segment_id: %d, begin: " PATTERNS_ADDR_FMT ", end: " PATTERNS_ADDR_FMT "", 
						name.first.c_str(), name.second, begin, end);
					break;
				}
			}
		}
	}

	void Initialize(uintptr_t begin, uintptr_t end)
	{
		PATTERNS_LOGIS("executable_meta::Initialize: name: %s, begin: " PATTERNS_ADDR_FMT ", end: " PATTERNS_ADDR_FMT "", m_name.c_str(), begin, end);
		
		if (begin >= end && begin != 0u && end != 0u)
		{
			PATTERNS_LOGE("executable_meta::Initialize: begin >= end");
			return;
		}
		if (begin == 0u && end == 0u)
		{
			PATTERNS_LOGW("executable_meta::Initialize: begin and end is 0. find all segments or sections in the process by default.");
			FindLibrarys();
			return;
		}
		if (end == 0u)
		{
			Initialize(begin);
			return;
		}
		if (begin == 0)
		{
			if (m_name.empty())
			{
				PATTERNS_DL_ADDR(end, info);
				if (info.dli_fbase == nullptr)
				{
					return;
				}
				if (info.dli_fname != nullptr)
				{
					m_name = info.dli_fname;
				}
				PATTERNS_DL_ADDR_CLEAN;
			}
			
			FindLibrarys();

			if (!m_sections.empty())
			{
				for (auto& section : m_sections)
				{
					if (section.second.first < end && end <= section.second.second)
					{
						begin = section.second.first;
						std::pair<const std::string, const std::string> name = section.first;
						m_sections.clear();
						m_sections.emplace(name, std::make_pair(begin, end));
						m_executable_sections.clear();
						m_executable_sections.emplace(name, std::make_pair(begin, end));

						PATTERNS_LOGIS("executable_meta::Initialize: lib_name: %s, section_name: %s, begin: " PATTERNS_ADDR_FMT ", end: " PATTERNS_ADDR_FMT "", 
							name.first.c_str(), name.second.c_str(), begin, end);
						break;
					}
				}
			}
			if (!m_segments.empty())
			{
				for (auto& segment : m_segments)
				{
					if (segment.second.first < end && end <= segment.second.second)
					{
						begin = segment.second.first;
						std::pair<const std::string, uint16_t> name = segment.first;
						m_segments.clear();
						m_segments.emplace(name, std::make_pair(begin, end));
						m_executable_segments.clear();
						m_executable_segments.emplace(name, std::make_pair(begin, end));

						PATTERNS_LOGIS("executable_meta::Initialize: lib_name: %s, segment_id: %d, begin: " PATTERNS_ADDR_FMT ", end: " PATTERNS_ADDR_FMT "", 
							name.first.c_str(), name.second, begin, end);
						break;
					}
				}
			}
			return;
		}

		std::pair<std::string, std::string> section_name;
		std::pair<std::string, uint16_t> segment_name;
		if (!m_name.empty())
		{
			FindLibrarys();

			if (!m_sections.empty())
			{
				for (auto& section : m_sections)
				{
					if (section.second.first <= begin && end <= section.second.second)
					{
						section_name = section.first;
						break;
					}
				}
			}

			if (!m_segments.empty())
			{
				for (auto& segment : m_segments)
				{
					if (segment.second.first <= begin && end <= segment.second.second)
					{
						segment_name = segment.first;
						goto end;
					}
				}
			}
			PATTERNS_LOGE("executable_meta: begin and end is not in the same segment or section.");
			return;
		}
	end:
		m_sections.clear();
		m_sections.emplace(section_name, std::make_pair(begin, end));
		m_executable_sections.clear();
		m_executable_sections.emplace(section_name, std::make_pair(begin, end));
		m_segments.clear();
		m_segments.emplace(segment_name, std::make_pair(begin, end));
		m_executable_segments.clear();
		m_executable_segments.emplace(segment_name, std::make_pair(begin, end));
	}

	executable_meta(uintptr_t begin, uintptr_t end, const std::string& lib_name)
		: executable_meta(lib_name)
	{
		Initialize(begin, end);
	}

	~executable_meta()
	{
		for (auto& elf : m_elf)
		{
			munmap(elf.first, elf.second);
		}
		m_elf.clear();
		m_name.clear();
		m_sections.clear();
		m_executable_sections.clear();
		m_segments.clear();
		m_executable_segments.clear();
	}

	inline const std::map<std::pair<const std::string, const std::string>, std::pair<uintptr_t, uintptr_t>>& get_sections(bool is_executable)
	{
		return is_executable ? m_executable_sections : m_sections;
	}

	inline const std::map<std::pair<const std::string, uint16_t>, std::pair<uintptr_t, uintptr_t>>& get_segments(bool is_executable)
	{
		return is_executable ? m_executable_segments : m_segments;
	}
};

namespace details
{

void basic_pattern_impl::Initialize(std::string_view pattern)
{
	// get the hash for the base pattern
#if PATTERNS_USE_HINTS
	m_hash = fnv_1()(pattern);
#endif

	// transform the base pattern from IDA format to canonical format
	TransformPattern(pattern, m_bytes, m_mask);

#if PATTERNS_USE_HINTS
	// if there's hints, try those first
#if PATTERNS_CAN_SERIALIZE_HINTS
	if (m_rangeStart == get_process_base(m_libName))
#endif
	{
		auto range = getHints().equal_range(m_hash);

		if (range.first != range.second)
		{
			std::for_each(range.first, range.second, [&] (const auto& hint)
			{
				ConsiderHint(hint.second);
			});

			// if the hints succeeded, we don't need to do anything more
			if (!m_matches.empty())
			{
				m_matched = true;
				return;
			}
		}
	}
#endif
}

void basic_pattern_impl::EnsureMatches(uint32_t maxCount)
{
	if (m_matched || (!m_rangeStart && !m_rangeEnd && m_libName.empty()))
	{
		return;
	}

	// scan the executable for code
	executable_meta executable = executable_meta(m_rangeStart, m_rangeEnd, m_libName);

	auto matchSuccess = [&](uintptr_t address)
	{
#if PATTERNS_USE_HINTS
		getHints().emplace(m_hash, address);
#else
		(void)address;
#endif

		return (m_matches.size() == maxCount);
	};

	const uint8_t* pattern = m_bytes.data();
	const uint8_t* mask = m_mask.data();
	const size_t maskSize = m_mask.size();
	const size_t lastWild = m_mask.find_last_not_of(uint8_t(0xFF));

	ptrdiff_t Last[256];

	std::fill(std::begin(Last), std::end(Last), lastWild == std::string::npos ? -1 : static_cast<ptrdiff_t>(lastWild));

	for (ptrdiff_t i = 0; i < static_cast<ptrdiff_t>(maskSize); ++i)
	{
		if (Last[pattern[i]] < i)
		{
			Last[pattern[i]] = i;
		}
	}

	static auto Matches = [&](uintptr_t begin, uintptr_t end) -> void
	{
		try
		{
			for (uintptr_t i = begin, ends = end - maskSize; i <= ends;)
			{
				uint8_t* ptr = reinterpret_cast<uint8_t*>(i);
				ptrdiff_t j = maskSize - 1;

				while ((j >= 0) && pattern[j] == (ptr[j] & mask[j])) j--;

				if (j < 0)
				{
					m_matches.emplace_back(ptr);
					if (matchSuccess(i))
					{
						break;
					}
					i++;
				}
				else
				{
					i += std::max(ptrdiff_t(1), j - Last[ptr[j]]);
				}
			}
		}
		catch (const std::exception& e)
		{
			PATTERNS_LOGES("Matches exceptional: %s", e.what());
		}
	};
	
	if (m_findSection)
	{
		auto& sections = executable.get_sections(m_findExecutable);
		for (auto& section : sections)
		{
			if (m_ignoreLibrarys.empty())
			{
				if (m_sectionNames.empty())
				{
					if (m_ignoreSections.empty())
					{
						Matches(section.second.first, section.second.second);
					}
					else
					{
						for (auto& ignoreSection : m_ignoreSections)
						{
							if (section.first.second != ignoreSection)
							{
								Matches(section.second.first, section.second.second);
							}
						}
					}
				}
				else
				{
					for (auto& sectionName : m_sectionNames)
					{
						if (section.first.second == sectionName)
						{
							if (m_ignoreSections.empty())
							{
								Matches(section.second.first, section.second.second);
							}
							else
							{
								for (auto& ignoreSection : m_ignoreSections)
								{
									if (section.first.second != ignoreSection)
									{
										Matches(section.second.first, section.second.second);
									}
								}
							}
						}
					}
				}
			}
			else
			{
				for (auto& ignoreLibrary : m_ignoreLibrarys)
				{
					if (section.first.first != ignoreLibrary)
					{
						if (m_sectionNames.empty())
						{
							if (m_ignoreSections.empty())
							{
								Matches(section.second.first, section.second.second);
							}
							else
							{
								for (auto& ignoreSection : m_ignoreSections)
								{
									if (section.first.second != ignoreSection)
									{
										Matches(section.second.first, section.second.second);
									}
								}
							}
						}
						else
						{
							for (auto& sectionName : m_sectionNames)
							{
								if (section.first.second == sectionName)
								{
									if (m_ignoreSections.empty())
									{
										Matches(section.second.first, section.second.second);
									}
									else
									{
										for (auto& ignoreSection : m_ignoreSections)
										{
											if (section.first.second != ignoreSection)
											{
												Matches(section.second.first, section.second.second);
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	else
	{
		auto& segments = executable.get_segments(m_findExecutable);
		for (auto& segment : segments)
		{
			if (m_ignoreLibrarys.empty())
			{
				Matches(segment.second.first, segment.second.second);
			}
			else
			{
				for (auto& ignoreLibrary : m_ignoreLibrarys)
				{
					if (segment.first.first != ignoreLibrary)
					{
						Matches(segment.second.first, segment.second.second);
					}
				}
			}
		}
	}

	m_matched = true;
}

bool basic_pattern_impl::ConsiderHint(uintptr_t offset)
{
	uint8_t* ptr = reinterpret_cast<uint8_t*>(offset);

#if PATTERNS_CAN_SERIALIZE_HINTS
	const uint8_t* pattern = m_bytes.data();
	const uint8_t* mask = m_mask.data();

	for (size_t i = 0, j = m_mask.size(); i < j; i++)
	{
		if (pattern[i] != (ptr[i] & mask[i]))
		{
			return false;
		}
	}
#endif

	m_matches.emplace_back(ptr);

	return true;
}

#if PATTERNS_USE_HINTS && PATTERNS_CAN_SERIALIZE_HINTS
void basic_pattern_impl::hint(uint64_t hash, uintptr_t address)
{
	auto& hints = getHints();

	auto range = hints.equal_range(hash);

	for (auto it = range.first; it != range.second; ++it)
	{
		if (it->second == address)
		{
			return;
		}
	}

	hints.emplace(hash, address);
}
#endif

}
}