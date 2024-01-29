# Copyright (c) 2024 晓梦大师/XMDS

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Android NDK - Message include
# form Google Android NDK
# https://github.com/android/ndk
# https://developer.android.google.cn/ndk/guides/ndk-build
# https://developer.android.google.cn/ndk/guides/android_mk
# https://developer.android.google.cn/ndk/guides/application_mk

$(info Android NDK - Message include)

ifeq ($(NDK_LOG), 1)
    $(warning Please use NDK_LOG=0 to disable the ndk log.)
endif

define message
    $(info $(1))
endef

define warning
    $(warning $(1))
endef

# use error end the build process
define error
    $(error $(1))
endef

define info
    $(call message, $(1))
endef

# use example:
# $(call info, "Hello World!")
# $(call warning, "Hello World!")
# $(call error, "Hello World!")
# $(call message, "Hello World!")
# $(call message, LOCAL_PATH: $(LOCAL_PATH))
# Android NDK - Message include end
