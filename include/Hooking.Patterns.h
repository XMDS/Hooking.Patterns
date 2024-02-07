/*
 * This file is part of the CitizenFX project - http://citizen.re/
 *
 * See LICENSE and MENTIONS in the root of the source tree for information
 * regarding licensing.
 */
 
/*
 * Copyright (c) 2024 晓梦大师/XMDS
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
// Created by XMDS on 2024-01-20

#ifndef HOOKING_PATTERNS
#define HOOKING_PATTERNS

#include <cassert>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <string_view>
#include <initializer_list>

#if defined(_CPPUNWIND) && !defined(PATTERNS_SUPPRESS_EXCEPTIONS)
#define PATTERNS_ENABLE_EXCEPTIONS
#endif

namespace hook
{
	struct assert_err_policy
	{
		static void count([[maybe_unused]] bool countMatches) { assert(countMatches); }
	};

#ifdef PATTERNS_ENABLE_EXCEPTIONS
	class txn_exception
	{
		// Deliberately empty for now
	};

#define TXN_CATCH() catch (const hook::txn_exception&) {}

	struct exception_err_policy
	{
		static void count(bool countMatches) { if (!countMatches) { throw txn_exception{}; } }
	};
#else
	struct exception_err_policy
	{
	};
#endif

	class pattern_match
	{
	private:
		void* m_pointer;

	public:
		inline pattern_match(void* pointer)
			: m_pointer(pointer)
		{
		}

		template<typename T>
		T* get(ptrdiff_t offset = 0) const
		{
			char* ptr = reinterpret_cast<char*>(m_pointer);
			return reinterpret_cast<T*>(ptr + offset);
		}
	};

	namespace details
	{
		ptrdiff_t get_process_base(const std::string& librarys);

		const std::string get_process_name();

		class basic_pattern_impl
		{
		protected:
			std::basic_string<uint8_t> m_bytes;
			std::basic_string<uint8_t> m_mask;

#if PATTERNS_USE_HINTS
			uint64_t m_hash = 0;
#endif

			std::vector<pattern_match> m_matches;

			bool m_matched = false;

			std::string m_libName;
			uintptr_t m_rangeStart;
			uintptr_t m_rangeEnd;

			std::vector<const std::string> m_sectionNames;

			bool m_findSection = false;
			bool m_findExecutable = true;

			std::vector<const std::string> m_ignoreLibrarys;
			std::vector<const std::string> m_ignoreSections;

		protected:
			void Initialize(std::string_view pattern);

			bool ConsiderHint(uintptr_t offset);

			void EnsureMatches(uint32_t maxCount);

			inline pattern_match _get_internal(size_t index) const
			{
				return m_matches[index];
			}

		private:
			explicit basic_pattern_impl(uintptr_t begin, uintptr_t end = 0)
				: m_rangeStart(begin), m_rangeEnd(end)
			{
			}

			explicit basic_pattern_impl(const std::string& lib_name, uintptr_t begin, uintptr_t end = 0)
				: m_libName(lib_name), m_rangeStart(begin), m_rangeEnd(end)
			{
			}

			explicit basic_pattern_impl(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end = 0)
				: m_libName(lib_name), m_rangeStart(begin), m_rangeEnd(end)
			{
				if (!section.empty())
				{
					m_sectionNames.emplace_back(section);
					m_findSection = true;
				}
			}

		public:
			explicit basic_pattern_impl()
				: m_libName(get_process_name()), m_rangeStart(0), m_rangeEnd(0)
			{
			}

			explicit basic_pattern_impl(std::string_view pattern)
				: basic_pattern_impl()
			{
				Initialize(std::move(pattern));
			}

			inline basic_pattern_impl(void* module, std::string_view pattern)
				: basic_pattern_impl(reinterpret_cast<uintptr_t>(module))
			{
				Initialize(std::move(pattern));
			}

			inline basic_pattern_impl(uintptr_t begin, uintptr_t end, std::string_view pattern)
				: basic_pattern_impl(begin, end)
			{
				Initialize(std::move(pattern));
			}

			inline basic_pattern_impl(const std::string& lib_name, void* module, std::string_view pattern)
				: basic_pattern_impl(lib_name, reinterpret_cast<uintptr_t>(module))
			{
				Initialize(std::move(pattern));
			}
			
			inline basic_pattern_impl(const std::string& lib_name, uintptr_t begin, uintptr_t end, std::string_view pattern)
				: basic_pattern_impl(lib_name, begin, end)
			{
				Initialize(std::move(pattern));
			}

			inline basic_pattern_impl(const std::string& lib_name, const std::string& section, std::string_view pattern)
				: basic_pattern_impl(lib_name, section, 0)
			{
				Initialize(std::move(pattern));
			}

			inline basic_pattern_impl(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, std::string_view pattern)
				: basic_pattern_impl(lib_name, section, begin, end)
			{
				Initialize(std::move(pattern));
			}

			explicit basic_pattern_impl(const std::string& lib_or_section_name, std::string_view pattern)
			{
				if (lib_or_section_name.empty())
				{
					return;
				}
				if (lib_or_section_name[0] != '.')
				{
					new(this) basic_pattern_impl(lib_or_section_name, get_process_base(lib_or_section_name));
					Initialize(std::move(pattern));
				}
				else
				{
					new(this) basic_pattern_impl(get_process_name(), lib_or_section_name, std::move(pattern));
				}
			}
			
			// Pretransformed patterns
			inline basic_pattern_impl(const std::string& lib_name, std::basic_string_view<uint8_t> bytes, std::basic_string_view<uint8_t> mask)
				: basic_pattern_impl(lib_name, get_process_base(lib_name))
			{
				assert(bytes.length() == mask.length());
				m_bytes = std::move(bytes);
				m_mask = std::move(mask);
			}

		protected:
#if PATTERNS_USE_HINTS && PATTERNS_CAN_SERIALIZE_HINTS
			// define a hint
			static void hint(uint64_t hash, uintptr_t address);
#endif
		};
	}

	template<typename err_policy>
	class basic_pattern : details::basic_pattern_impl
	{
	public:
		using details::basic_pattern_impl::basic_pattern_impl;

		inline basic_pattern&& section(std::initializer_list<const std::string> sections = {})
		{
			if (sections.size())
			{
				for (const std::string& section : sections)
				{
					if (!section.empty()) m_sectionNames.emplace_back(section);
				}
			}
			m_findSection = true;
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& segment()
		{
			m_findSection = false;
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& executable(bool findExecutable = true)
		{
			m_findExecutable = findExecutable;
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& ignore_lib(std::initializer_list<const std::string> lib_names = {})
		{
			if (lib_names.size())
			{
				for (const std::string& lib_name : lib_names)
				{
					if (!lib_name.empty()) m_ignoreLibrarys.emplace_back(lib_name);
				}
			}
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& ignore_section(std::initializer_list<const std::string> sections = {})
		{
			if (sections.size())
			{
				for (const std::string& section : sections)
				{
					if (!section.empty()) m_ignoreSections.emplace_back(section);
				}
			}
			return std::forward<basic_pattern>(*this);
		}
		
		inline basic_pattern&& count(uint32_t expected)
		{
			EnsureMatches(expected);
			err_policy::count(m_matches.size() == expected);
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& count_hint(uint32_t expected)
		{
			EnsureMatches(expected);
			return std::forward<basic_pattern>(*this);
		}

		inline basic_pattern&& clear(void* module = nullptr)
		{
			if (module)
			{
				this->m_rangeStart = reinterpret_cast<uintptr_t>(module);
				this->m_rangeEnd = 0;
			}

			m_matches.clear();
			m_matched = false;
			m_libName.clear();
			m_findSection = false;
			m_findExecutable = true;
			m_sectionNames.clear();
			m_ignoreLibrarys.clear();
			m_ignoreSections.clear();
			return std::forward<basic_pattern>(*this);
		}

		inline size_t size()
		{
			EnsureMatches(UINT32_MAX);
			return m_matches.size();
		}

		inline bool empty()
		{
			return size() == 0;
		}

		inline pattern_match get(size_t index)
		{
			EnsureMatches(UINT32_MAX);
			return _get_internal(index);
		}

		inline pattern_match get_one()
		{
			return std::forward<basic_pattern>(*this).count(1)._get_internal(0);
		}

		template<typename T = void>
		inline auto get_first(ptrdiff_t offset = 0)
		{
			return get_one().template get<T>(offset);
		}

		template <typename Pred>
		inline Pred for_each_result(Pred&& pred)
		{
			EnsureMatches(UINT32_MAX);
			for (auto it : m_matches)
			{
				std::forward<Pred>(pred)(it);
			}
			return std::forward<Pred>(pred);
		}

	public:
#if PATTERNS_USE_HINTS && PATTERNS_CAN_SERIALIZE_HINTS
		// define a hint
		static void hint(uint64_t hash, uintptr_t address)
		{
			details::basic_pattern_impl::hint(hash, address);
		}
#endif
	};

	using pattern = basic_pattern<assert_err_policy>;

	inline auto make_module_pattern(void* module, std::string_view bytes)
	{
		return pattern(module, std::move(bytes));
	}
	
	inline auto make_module_pattern(const std::string& lib_name, void* module, std::string_view bytes)
	{
		return pattern(lib_name, module, std::move(bytes));
	}
	
	inline auto make_range_pattern(uintptr_t begin, uintptr_t end, std::string_view bytes)
	{
		return pattern(begin, end, std::move(bytes));
	}

	inline auto make_range_pattern(const std::string& lib_name, uintptr_t begin, uintptr_t end, std::string_view bytes)
	{
		return pattern(lib_name, begin, end, std::move(bytes));
	}
	
	inline auto make_section_pattern(const std::string& section, std::string_view bytes)
	{
		return pattern(section, std::move(bytes));
	}
	
	inline auto make_section_pattern(const std::string& lib_name, const std::string& section, std::string_view bytes)
	{
		return pattern(lib_name, section, std::move(bytes));
	}

	inline auto make_section_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, std::string_view bytes)
	{
		return pattern(lib_name, section, begin, end, std::move(bytes));
	}
	
	inline auto make_string_pattern(uintptr_t begin, uintptr_t end, const std::string& str)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
		std::stringstream ss;

		size_t len = str.size();
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(begin, end, ss.str());
	}

	inline auto make_string_pattern(const std::string& lib_name, uintptr_t begin, uintptr_t end, const std::string& str)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
		std::stringstream ss;

		size_t len = str.size();
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, begin, end, ss.str());
	}

	inline auto make_string_pattern(const std::string& lib_or_section_name, const std::string& str)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
		std::stringstream ss;

		size_t len = str.size();
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_or_section_name, ss.str());
	}

	inline auto make_string_pattern(const std::string& lib_name, const std::string& section, const std::string& str)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
		std::stringstream ss;

		size_t len = str.size();
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, section, ss.str());
	}
	
	inline auto make_string_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, const std::string& str)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
		std::stringstream ss;

		size_t len = str.size();
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, section, begin, end, ss.str());
	}

	template <typename T>
	inline auto make_data_pattern(const std::string& lib_name, const T& data)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
		std::stringstream ss;

		size_t len = sizeof(T);
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, ss.str());
	}
	
	template <typename T>
	inline auto make_data_pattern(uintptr_t begin, uintptr_t end, const T& data)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
		std::stringstream ss;

		size_t len = sizeof(T);
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(begin, end, ss.str());
	}
	
	template <typename T>
	inline auto make_data_pattern(const std::string& lib_name, const std::string& section, const T& data)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
		std::stringstream ss;

		size_t len = sizeof(T);
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, section, ss.str());
	}

	template <typename T>
	inline auto make_data_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, const T& data)
	{
		const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
		std::stringstream ss;

		size_t len = sizeof(T);
		for (size_t i = 0; i < len; ++i)
		{
			ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
		}
		return pattern(lib_name, section, begin, end, ss.str());
	}
	
	template<typename T = void>
	inline auto get_pattern(std::string_view pattern_string, ptrdiff_t offset = 0)
	{
		return pattern(std::move(pattern_string)).get_first<T>(offset);
	}

	inline auto module_pattern(void* module, std::string_view bytes)
	{
		return make_module_pattern(module, std::move(bytes));
	}

	inline auto range_pattern(uintptr_t begin, uintptr_t end, std::string_view bytes)
	{
		return make_range_pattern(begin, end, std::move(bytes));
	}
	
	inline auto section_pattern(const std::string& section, std::string_view bytes)
	{
		return make_section_pattern(section, std::move(bytes));
	}
	
	namespace txn
	{
		using pattern = hook::basic_pattern<exception_err_policy>;

		inline auto make_module_pattern(void* module, std::string_view bytes)
		{
			return pattern(module, std::move(bytes));
		}

		inline auto make_module_pattern(const std::string& lib_name, void* module, std::string_view bytes)
		{
			return pattern(lib_name, module, std::move(bytes));
		}
		
		inline auto make_range_pattern(uintptr_t begin, uintptr_t end, std::string_view bytes)
		{
			return pattern(begin, end, std::move(bytes));
		}
		
		inline auto make_range_pattern(const std::string& lib_name, uintptr_t begin, uintptr_t end, std::string_view bytes)
		{
			return pattern(lib_name, begin, end, std::move(bytes));
		}

		inline auto make_section_pattern(const std::string& section, std::string_view bytes)
		{
			return pattern(section, std::move(bytes));
		}

		inline auto make_section_pattern(const std::string& lib_name, const std::string& section, std::string_view bytes)
		{
			return pattern(lib_name, section, std::move(bytes));
		}

		inline auto make_section_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, std::string_view bytes)
		{
			return pattern(lib_name, section, begin, end, std::move(bytes));
		}

		inline auto make_string_pattern(uintptr_t begin, uintptr_t end, const std::string& str)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
			std::stringstream ss;

			size_t len = str.size();
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(begin, end, ss.str());
		}

		inline auto make_string_pattern(const std::string& lib_name, uintptr_t begin, uintptr_t end, const std::string& str)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
			std::stringstream ss;

			size_t len = str.size();
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, begin, end, ss.str());
		}

		inline auto make_string_pattern(const std::string& lib_or_section_name, const std::string& str)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
			std::stringstream ss;

			size_t len = str.size();
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_or_section_name, ss.str());
		}

		inline auto make_string_pattern(const std::string& lib_name, const std::string& section, const std::string& str)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
			std::stringstream ss;

			size_t len = str.size();
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, section, ss.str());
		}

		inline auto make_string_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, const std::string& str)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(str.data());
			std::stringstream ss;

			size_t len = str.size();
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, section, begin, end, ss.str());
		}

		template <typename T>
		inline auto make_data_pattern(const std::string& lib_name, const T& data)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
			std::stringstream ss;

			size_t len = sizeof(T);
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, ss.str());
		}

		template <typename T>
		inline auto make_data_pattern(uintptr_t begin, uintptr_t end, const T& data)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
			std::stringstream ss;

			size_t len = sizeof(T);
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(begin, end, ss.str());
		}

		template <typename T>
		inline auto make_data_pattern(const std::string& lib_name, const std::string& section, const T& data)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
			std::stringstream ss;

			size_t len = sizeof(T);
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, section, ss.str());
		}

		template <typename T>
		inline auto make_data_pattern(const std::string& lib_name, const std::string& section, uintptr_t begin, uintptr_t end, const T& data)
		{
			const unsigned char* bytes = reinterpret_cast<const unsigned char*>(&data);
			std::stringstream ss;

			size_t len = sizeof(T);
			for (size_t i = 0; i < len; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(bytes[i]) << " ";
			}
			return pattern(lib_name, section, begin, end, ss.str());
		}
		
		template<typename T = void>
		inline auto get_pattern(std::string_view pattern_string, ptrdiff_t offset = 0)
		{
			return pattern(std::move(pattern_string)).get_first<T>(offset);
		}

		inline auto module_pattern(void* module, std::string_view bytes)
		{
			return make_module_pattern(module, std::move(bytes));
		}

		inline auto range_pattern(uintptr_t begin, uintptr_t end, std::string_view bytes)
		{
			return make_range_pattern(begin, end, std::move(bytes));
		}

		inline auto section_pattern(const std::string& section, std::string_view bytes)
		{
			return make_section_pattern(section, std::move(bytes));
		}
	}
}

#endif // !HOOKING_PATTERNS