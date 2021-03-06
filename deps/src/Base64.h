/** \file Base64.h
 **	\date  2004-02-13
 **	\author grymse@alhem.net
**/
/*
Copyright (C) 2004-2006  Anders Hedstrom

This library is made available under the terms of the GNU GPL.

If you would like to use this library in a closed-source application,
a separate license agreement is available. For information about
the closed-source license agreement for the C++ sockets library,
please visit http://www.alhem.net/Sockets/license.html and/or
email license@alhem.net.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/
#ifndef __BASE64_H__
#define __BASE64_H__

#include <ctype.h>
#include <stdio.h>

/** \defgroup util Utilities */

/** Base64 encode/decode.
        \ingroup util */
class CBase64 {
public:
    CBase64();
    virtual ~CBase64();
    static inline bool is_base64(const unsigned char c)
    {
        return (isalnum(c) || (c == '+') || (c == '/'));
    };
    void Encode(const unsigned char*, unsigned int len);
    void Decode(const unsigned char*, unsigned int len);
    const char* GetOutput();
    int GetOutputLength();

protected:
    char* m_output;
    int m_length;
};

#endif // __BASE64_H__
