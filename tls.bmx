' Copyright (c) 2023 Carl A Husberg
' 
' This software is provided 'as-is', without any express or implied
' warranty. In no event will the authors be held liable for any damages
' arising from the use of this software.
' 
' Permission is granted to anyone to use this software for any purpose,
' including commercial applications, and to alter it and redistribute it
' freely, subject to the following restrictions:
' 
' 1. The origin of this software must not be misrepresented; you must not
'    claim that you wrote the original software. If you use this software
'    in a product, an acknowledgment in the product documentation would be
'    appreciated but is not required.
' 2. Altered source versions must be plainly marked as such, and must not be
'    misrepresented as being the original software.
' 3. This notice may not be removed or altered from any source distribution.
SuperStrict

Rem
bbdoc:
End Rem
Module CAH.TLS

ModuleInfo "Version: 1.00"
ModuleInfo "License: zlib/libpng"
ModuleInfo "Copyright: 2023 Carl A Husberg"

ModuleInfo "History: 1.00 Initial Release"

Framework BRL.Blitz
Import Net.mbedtls
Import BRL.StandardIO

Include "src\server.bmx"
Include "src\stream.bmx"