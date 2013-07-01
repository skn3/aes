#rem
* License: MIT
* This code was ported from the Gibberish Javascript AES library on contract paid for by Lee Wade
* Author: Skn3 / Jonathan Pittock
* Email: jon@skn3.com

ORIGINAL LICENSE AND INFO
* Gibberish-AES 
* A lightweight Javascript Libray for OpenSSL compatible AES CBC encryption.
*
* Author: Mark Percival
* Email: mark@mpercival.com
* Copyright: Mark Percival - http:'mpercival.com 2008
*
* With thanks to:
* Josh Davis - http:'www.josh-davis.org/ecmaScrypt
* Chris Veness - http:'www.movable-type.co.uk/scripts/aes.html
* Michel I. Gallant - http:'www.jensign.com/
* Jean-Luc Cooke <jlcooke@certainkey.com> 2012-07-12: added strhex + invertArr to compress g2x/g3x/g9x/gbx/gex/sBox/sBoxInv/rCon saving over 7KB, and added encString, decString, also made the MD5_ routine more easlier compressible using yuicompressor.
*

'version 2
' - fixed exception not being caught
' - fixed string bounds on utf8decode now throws an exception
'version 1
' - first commit

*
#end

'version 2
' - fixed minor typo on win8 native filename
'version 1
' - first commit

Strict

Import monkey.math

Private
Import "native/aes.${TARGET}.${LANG}"

Extern
#If LANG<>"cpp"
	Function Lsr:Int(number:Int, shiftBy:Int) = "AESGlue.Lsr"
	Function Lsl:Int(number:Int, shiftBy:Int) = "AESGlue.Lsl"
#Else
	Function Lsr:Int(number:Int, shiftBy:Int) = "AESGlue::Lsr"
	Function Lsl:Int(number:Int, shiftBy:Int) = "AESGlue::Lsl"
#End
Public

Public
Class AESException Extends Throwable
	Field message:String
	
	Method New(message:String)
		Self.message = message
	End
End

Class AES
	Private
	Const base64Chars:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	Global base64Lookup:Int[] =[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 0, 0, 0, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	
	Global nr:= 14' Default to 256 Bit Encryption 
	Global nk:= 8
	Global decrypt:= False
	
	Global sBox:Int[] = StrHex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16", 2)
	Global sBoxInv:Int[] = InvertArray(sBox)
	Global rCon:Int[] = StrHex("01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc591", 2)
	Global g2x:Int[] = GX(2)
	Global g3x:Int[] = GX(3)
	Global g9x:Int[] = GX(9)
	Global gbx:Int[] = GX($b)
	Global gdx:Int[] = GX($d)
	Global gex:Int[] = GX($e)

	'helper functions
	Function CombineStrings:String(strings:String[])
		' --- combine array of strings ---
		Local temp:String
		For Local index:= 0 Until strings.Length
			temp += strings[index]
		Next
		Return temp
	End
	
	Function CombineArrays:Int[] (array1:Int[])
		' --- combine 1 arrays ---
		'wrong name but meh
		Local temp:Int[array1.Length]
		Local index:Int
		Local offset:Int
		
		For index = 0 Until array1.Length
			temp[offset] = array1[index]
			offset += 1
		Next
		
		Return temp
	End
	
	Function CombineArrays:Int[] (array1:Int[], array2:Int[])
		' --- combine 2 arrays ---
		Local temp:Int[array1.Length + array2.Length]
		Local index:Int
		Local offset:Int
		
		For index = 0 Until array1.Length
			temp[offset] = array1[index]
			offset += 1
		Next
		
		For index = 0 Until array2.Length
			temp[offset] = array2[index]
			offset += 1
		Next
		
		Return temp
	End
	
	Function CombineArrays:Int[] (array1:Int[], array2:Int[], array3:Int[], array4:Int[])
		' --- combine 2 arrays ---
		Local temp:Int[array1.Length + array2.Length + array3.Length + array4.Length]
		Local index:Int
		Local offset:Int
		
		For index = 0 Until array1.Length
			temp[offset] = array1[index]
			offset += 1
		Next
		
		For index = 0 Until array2.Length
			temp[offset] = array2[index]
			offset += 1
		Next
		
		For index = 0 Until array3.Length
			temp[offset] = array3[index]
			offset += 1
		Next
		
		For index = 0 Until array4.Length
			temp[offset] = array4[index]
			offset += 1
		Next
		
		Return temp
	End
	
	Function CombineArrays:Int[][] (array1:Int[][], array2:Int[][])
		' --- combine 2 arrays ---
		Local temp:Int[array1.Length + array2.Length][]
		Local index1:Int
		Local index2:Int
		Local offset:Int
		
		For index1 = 0 Until array1.Length
			temp[offset] = New Int[array1[index1].Length]
			
			For index2 = 0 Until array1[index1].Length
				temp[offset][index2] = array1[index1][index2]
			Next
			
			offset += 1
		Next
		
		For index1 = 0 Until array2.Length
			temp[offset] = New Int[array2[index1].Length]
			
			For index2 = 0 Until array2[index1].Length
				temp[offset][index2] = array2[index1][index2]
			Next
			
			offset += 1
		Next
		
		Return temp
	End
	
	Function InvertArray:Int[] (arr:Int[])
		Local ret:Int[arr.Length]
		For Local i:= 0 Until arr.Length
			ret[arr[i]] = i
		Next
		
		Return ret
	End
	
	Function IntToHex:String(i:Int)
		''p=32-bit
		Local r:Int = i, s:Int, p:Int = 32, n:Int[ (p / 4) + 1]
		While p > 0
			s = (r & $f) + 48
			If s > 57 s += 7
			
			p -= 4
			n[p Shr 2] = s
			r = r Shr 4
		Wend
		
		'trim leading 0
		Local start:Int = 0
		For p = 0 Until n.Length
			If n[p] <> 48 Exit
			start += 1
		Next
		If start > 0 n = n[start ..]
		
		Return String.FromChars(n)
	End
	
	Function HexToInt:Int(hexstr:String)
		Local rv:Int = 0
		For Local i:Int = 0 Until hexstr.Length
			Local val:Int = hexstr[i]
			If val >= 48 And val <= 57 Then
				rv = rv * 16 + val - 48
			ElseIf val >= 65 And val <= 70 Then
				rv = rv * 16 + val - 55
			ElseIf val >= 97 And val <= 102 Then
				rv = rv * 16 + val - 87
			End
		Next
		Return rv
	End
	
	Function StrHex:Int[] (str:String, size:Int)
		Local ret:Int[str.Length / size]
		Local index:Int
		
		While index < str.Length
			ret[index / size] = HexToInt(str[index .. index + size])
			index += size
		Wend
		
		Return ret
	End
	
	Function GXX:Int(a:Int, b:Int)
		Local i:Int
		Local ret:Int

		For i = 0 Until 8
			If (b & 1) = 1 ret = ret ~ a
			
			'xmult
			If a > $7f
				a = $11b ~ Lsl(a, 1)
			Else
				a = Lsl(a, 1)
			EndIf
			
			b = Lsr(b, 1)
		Next

		Return ret
	End
	
	Function GX:Int[] (x:Int)
		Local r:Int[256]
		
		For Local i:= 0 Until 256
			r[i] = GXX(x, i)
		Next
		
		Return r
	End
	
	'gibberish functions
	Function PadBlock:Int[] (byteArray:Int[])
		Local temp:Int[16]
		Local index:Int
		
		If byteArray.Length < 16
			Local pad:= 16 - byteArray.Length
			For index = 0 Until 16
				temp[index] = pad
			Next
		EndIf
		
		For index = 0 Until byteArray.Length
			temp[index] = byteArray[index]
		Next
		
		Return temp
	End

	Function BlockToString:string(block:Int[], lastBlock:Bool = False)
		Local temp:int[16]
		Local padding:Int
		Local index:Int
		
		If lastBlock
			padding = block[15]
			If padding > 16 Throw New AESException("Decryption error: Maybe bad key")
			If padding = 16 Return ""

			For index = 0 Until 16 - padding
				temp[index] = block[index]
			Next
		Else
			For index = 0 Until 16
				temp[index] = block[index]
			Next
		EndIf
		
		Return String.FromChars(temp)
	End

	Function RandomArray:Int[] (num:Int)	
		Local result:int[num]		
		For Local index:= 0 Until num
			result[index] = Floor(Rnd(0.0, 1.0) * 256)'done this way becauses trying to match js code
			'result[index] = index'this is a non random salt so hopefully we will have the same data now!
		Next
		Return result
	End

	Function SubBytes:Int[] (state:Int[])
		Local s:Int[]
		If decrypt
			s = sBoxInv
		Else
			s = sBox
		EndIf
		
		Local temp:int[16]
		Local index:Int
		
		For index = 0 Until 16
			'If state[index] < 0 or state[index] >= s.Length Throw New AESException("Something went wrong!")
			temp[index] = s[state[index]]
		Next
		
		Return temp
	End

	Function ShiftRows:Int[] (state:Int[])
		Local temp:int[16]
		
		Local shiftBy:Int[]
		If decrypt
			shiftBy =[0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
		Else
			shiftBy =[0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
		EndIf
		Local index:Int
		
		For index = 0 Until 16
			temp[index] = state[shiftBy[index]]
		Next
		
		Return temp
	End

	Function MixColumns:Int[] (state:Int[])
		Local temp:Int[16]
		Local c:Int
		
		If decrypt = False
			For c = 0 Until 4
				temp[c * 4] = g2x[state[c * 4]] ~ g3x[state[1 + c * 4]] ~ state[2 + c * 4] ~ state[3 + c * 4]
				temp[1 + c * 4] = state[c * 4]~  g2x[state[1 + c * 4]] ~ g3x[state[2 + c * 4]] ~ state[3 + c * 4]
				temp[2 + c * 4] = state[c * 4]~  state[1 + c * 4] ~ g2x[state[2 + c * 4]] ~ g3x[state[3 + c * 4]]
				temp[3 + c * 4] = g3x[state[c * 4]]~  state[1 + c * 4] ~ state[2 + c * 4] ~ g2x[state[3 + c * 4]]
			Next
		Else
			For c = 0 Until 4
				temp[c * 4] = gex[state[c * 4]]~  gbx[state[1 + c * 4]] ~ gdx[state[2 + c * 4]] ~ g9x[state[3 + c * 4]]
				temp[1 + c * 4] = g9x[state[c * 4]]~  gex[state[1 + c * 4]] ~ gbx[state[2 + c * 4]] ~ gdx[state[3 + c * 4]]
				temp[2 + c * 4] = gdx[state[c * 4]]~  g9x[state[1 + c * 4]] ~ gex[state[2 + c * 4]] ~ gbx[state[3 + c * 4]]
				temp[3 + c * 4] = gbx[state[c * 4]]~  gdx[state[1 + c * 4]] ~ g9x[state[2 + c * 4]] ~ gex[state[3 + c * 4]]
			Next
		EndIf
		
		Return temp
	End

	Function AddRoundKey:Int[] (state:Int[], words:int[][], round:Int)
		Local temp:int[16]
		Local index:Int
		
		For index = 0 Until 16
			temp[index] = state[index] ~ words[round][index]
		Next
		
		Return temp
	End

	Function XORBlocks:Int[] (block1:Int[], block2:Int[])
		Local temp:int[16]
		Local index:Int
		
		For index = 0 Until 16
			temp[index] = block1[index] ~ block2[index]
		Next
		
		Return temp
	End

	Function SubWord:Int[] (w:int[])
		'apply SBox to 4-byte word w
		For Local index:= 0 Until 4
			w[index] = sBox[w[index]]
		Next
		Return w
	End

	Function RotWord:Int[](w:int[])
		'rotate 4 - byte word w left by one byte
		Local tmp0:Int = w[0]
		For Local index:= 0 Until 3
			w[index] = w[index + 1]
		Next
		w[3] = tmp0
		Return w
	End
	
	'md5 helper functions
	Function MD5_RotateLeft:Int(lValue:Int, iShiftBits:Int)
		Return Lsl(lValue, iShiftBits) | Lsr(lValue, 32 - iShiftBits)
	End
	
	Function MD5_AddUnsigned:Int(lX:Int, lY:Int)
		Local lX4:Int
		Local lY4:Int
		Local lX8:Int
		Local lY8:Int
		Local lResult:Int
		
		lX8 = (lX & -2147483648)'$80000000)
		lY8 = (lY & - 2147483648)'$80000000)
		lX4 = (lX & $40000000)
		lY4 = (lY & $40000000)
		lResult = (lX & $3FFFFFFF) + (lY & $3FFFFFFF)
		If lX4 & lY4
			'Return lResult ~ $80000000 ~ lX8 ~ lY8
			Return lResult ~ - 2147483648 ~ lX8 ~ lY8
		EndIf
		
		If lX4 | lY4
			If lResult & $40000000
				Return lResult ~ $C0000000 ~ lX8 ~ lY8
			Else
				Return lResult ~ $40000000 ~ lX8 ~ lY8
			EndIf
		Else
			Return lResult ~ lX8 ~ lY8
		EndIf
	End
	
	Function MD5_F:Int(x:Int, y:Int, z:Int)
		Return (x & y) | ( ( ~ x) & z)
	End
	
	Function MD5_G:Int(x:Int, y:Int, z:Int)
		Return (x & z) | (y & ( ~ z))
	End
	
	Function MD5_H:Int(x:Int, y:Int, z:Int)
		Return (x ~ y ~ z)
	End
	
	Function MD5_FuncI:Int(x:Int, y:Int, z:Int)
		Return (y ~ (x | ( ~ z)))
	End
	
	Function MD5_FF:Int(a:Int, b:Int, c:Int, d:Int, x:Int, s:Int, ac:Int)
		a = MD5_AddUnsigned(a, MD5_AddUnsigned(MD5_AddUnsigned(MD5_F(b, c, d), x), ac))
		Return MD5_AddUnsigned(MD5_RotateLeft(a, s), b)
	End
	
	Function MD5_GG:Int(a:Int, b:Int, c:Int, d:Int, x:Int, s:Int, ac:Int)
		a = MD5_AddUnsigned(a, MD5_AddUnsigned(MD5_AddUnsigned(MD5_G(b, c, d), x), ac))
		Return MD5_AddUnsigned(MD5_RotateLeft(a, s), b)
	End
	
	Function MD5_HH:Int(a:Int, b:Int, c:Int, d:Int, x:Int, s:Int, ac:Int)
		a = MD5_AddUnsigned(a, MD5_AddUnsigned(MD5_AddUnsigned(MD5_H(b, c, d), x), ac))
		return MD5_AddUnsigned(MD5_RotateLeft(a, s), b)
	End
	
	Function MD5_II:Int(a:Int, b:Int, c:Int, d:Int, x:Int, s:Int, ac:Int)
		a = MD5_AddUnsigned(a, MD5_AddUnsigned(MD5_AddUnsigned(MD5_FuncI(b, c, d), x), ac))
		Return MD5_AddUnsigned(MD5_RotateLeft(a, s), b)
	End
	
	Function MD5_ConvertToWordArray:Int[] (numArr:Int[])
		Local lWordCount:int
		Local lMessageLength:Int = numArr.Length
		Local lNumberOfWords_temp1:Int = lMessageLength + 8
		Local lNumberOfWords_temp2:Int = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 Mod 64)) / 64
		Local lNumberOfWords:Int = (lNumberOfWords_temp2 + 1) * 16
		
		Local lWordArray:Int[lNumberOfWords]'lNumberOfWords???
		Local lBytePosition:Int = 0
		Local lByteCount:Int = 0
		
		While lByteCount < lMessageLength
			lWordCount = (lByteCount - (lByteCount Mod 4)) / 4
			lBytePosition = (lByteCount Mod 4) * 8
			lWordArray[lWordCount] = (lWordArray[lWordCount] | (Lsl(numArr[lByteCount], lBytePosition)))
			lByteCount += 1
		Wend
		
		lWordCount = (lByteCount - (lByteCount Mod 4)) / 4
		lBytePosition = (lByteCount Mod 4) * 8
		lWordArray[lWordCount] = lWordArray[lWordCount] | (Lsl($80, lBytePosition))
		lWordArray[lNumberOfWords - 2] = Lsl(lMessageLength, 3)
		lWordArray[lNumberOfWords - 1] = Lsr(lMessageLength, 29)
		
		Return lWordArray
	End
	
	Function MD5_WordToHex:Int[] (lValue:Int)
		Local lByte:Int
		Local lCount:Int
		Local wordToHexArr:Int[4]
		
		For lCount = 0 To 3
			lByte = Lsr(lValue, (lCount * 8)) & 255
			wordToHexArr[lCount] = lByte
		Next
		
		Return wordToHexArr
	End
	
	' ------------------------ public api ------------------------------
	Public
	
	'encoding api
	Function EncodeMD5:Int[] (numArr:Int[])
		' --- encode md5 ---
		Local x:Int[]
		Local k:Int
		Local AA:Int
		Local BB:Int
		Local CC:Int
		Local DD:Int
		Local a:Int
		Local b:Int
		Local c:Int
		Local d:Int
		
		Local rnd:Int[] = StrHex("67452301efcdab8998badcfe10325476d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391", 8)
	
		x = MD5_ConvertToWordArray(numArr)
	
		a = rnd[0]
		b = rnd[1]
		c = rnd[2]
		d = rnd[3]
	
		For k = 0 Until x.Length Step 16
			AA = a
			BB = b
			CC = c
			DD = d
			a = MD5_FF(a, b, c, d, x[k + 0], 7, rnd[4])
			d = MD5_FF(d, a, b, c, x[k + 1], 12, rnd[5])
			c = MD5_FF(c, d, a, b, x[k + 2], 17, rnd[6])
			b = MD5_FF(b, c, d, a, x[k + 3], 22, rnd[7])
			a = MD5_FF(a, b, c, d, x[k + 4], 7, rnd[8])
			d = MD5_FF(d, a, b, c, x[k + 5], 12, rnd[9])
			c = MD5_FF(c, d, a, b, x[k + 6], 17, rnd[10])
			b = MD5_FF(b, c, d, a, x[k + 7], 22, rnd[11])
			a = MD5_FF(a, b, c, d, x[k + 8], 7, rnd[12])
			d = MD5_FF(d, a, b, c, x[k + 9], 12, rnd[13])
			c = MD5_FF(c, d, a, b, x[k + 10], 17, rnd[14])
			b = MD5_FF(b, c, d, a, x[k + 11], 22, rnd[15])
			a = MD5_FF(a, b, c, d, x[k + 12], 7, rnd[16])
			d = MD5_FF(d, a, b, c, x[k + 13], 12, rnd[17])
			c = MD5_FF(c, d, a, b, x[k + 14], 17, rnd[18])
			b = MD5_FF(b, c, d, a, x[k + 15], 22, rnd[19])
			a = MD5_GG(a, b, c, d, x[k + 1], 5, rnd[20])
			d = MD5_GG(d, a, b, c, x[k + 6], 9, rnd[21])
			c = MD5_GG(c, d, a, b, x[k + 11], 14, rnd[22])
			b = MD5_GG(b, c, d, a, x[k + 0], 20, rnd[23])
			a = MD5_GG(a, b, c, d, x[k + 5], 5, rnd[24])
			d = MD5_GG(d, a, b, c, x[k + 10], 9, rnd[25])
			c = MD5_GG(c, d, a, b, x[k + 15], 14, rnd[26])
			b = MD5_GG(b, c, d, a, x[k + 4], 20, rnd[27])
			a = MD5_GG(a, b, c, d, x[k + 9], 5, rnd[28])
			d = MD5_GG(d, a, b, c, x[k + 14], 9, rnd[29])
			c = MD5_GG(c, d, a, b, x[k + 3], 14, rnd[30])
			b = MD5_GG(b, c, d, a, x[k + 8], 20, rnd[31])
			a = MD5_GG(a, b, c, d, x[k + 13], 5, rnd[32])
			d = MD5_GG(d, a, b, c, x[k + 2], 9, rnd[33])
			c = MD5_GG(c, d, a, b, x[k + 7], 14, rnd[34])
			b = MD5_GG(b, c, d, a, x[k + 12], 20, rnd[35])
			a = MD5_HH(a, b, c, d, x[k + 5], 4, rnd[36])
			d = MD5_HH(d, a, b, c, x[k + 8], 11, rnd[37])
			c = MD5_HH(c, d, a, b, x[k + 11], 16, rnd[38])
			b = MD5_HH(b, c, d, a, x[k + 14], 23, rnd[39])
			a = MD5_HH(a, b, c, d, x[k + 1], 4, rnd[40])
			d = MD5_HH(d, a, b, c, x[k + 4], 11, rnd[41])
			c = MD5_HH(c, d, a, b, x[k + 7], 16, rnd[42])
			b = MD5_HH(b, c, d, a, x[k + 10], 23, rnd[43])
			a = MD5_HH(a, b, c, d, x[k + 13], 4, rnd[44])
			d = MD5_HH(d, a, b, c, x[k + 0], 11, rnd[45])
			c = MD5_HH(c, d, a, b, x[k + 3], 16, rnd[46])
			b = MD5_HH(b, c, d, a, x[k + 6], 23, rnd[47])
			a = MD5_HH(a, b, c, d, x[k + 9], 4, rnd[48])
			d = MD5_HH(d, a, b, c, x[k + 12], 11, rnd[49])
			c = MD5_HH(c, d, a, b, x[k + 15], 16, rnd[50])
			b = MD5_HH(b, c, d, a, x[k + 2], 23, rnd[51])
			a = MD5_II(a, b, c, d, x[k + 0], 6, rnd[52])
			d = MD5_II(d, a, b, c, x[k + 7], 10, rnd[53])
			c = MD5_II(c, d, a, b, x[k + 14], 15, rnd[54])
			b = MD5_II(b, c, d, a, x[k + 5], 21, rnd[55])
			a = MD5_II(a, b, c, d, x[k + 12], 6, rnd[56])
			d = MD5_II(d, a, b, c, x[k + 3], 10, rnd[57])
			c = MD5_II(c, d, a, b, x[k + 10], 15, rnd[58])
			b = MD5_II(b, c, d, a, x[k + 1], 21, rnd[59])
			a = MD5_II(a, b, c, d, x[k + 8], 6, rnd[60])
			d = MD5_II(d, a, b, c, x[k + 15], 10, rnd[61])
			c = MD5_II(c, d, a, b, x[k + 6], 15, rnd[62])
			b = MD5_II(b, c, d, a, x[k + 13], 21, rnd[63])
			a = MD5_II(a, b, c, d, x[k + 4], 6, rnd[64])
			d = MD5_II(d, a, b, c, x[k + 11], 10, rnd[65])
			c = MD5_II(c, d, a, b, x[k + 2], 15, rnd[66])
			b = MD5_II(b, c, d, a, x[k + 9], 21, rnd[67])
			a = MD5_AddUnsigned(a, AA)
			b = MD5_AddUnsigned(b, BB)
			c = MD5_AddUnsigned(c, CC)
			d = MD5_AddUnsigned(d, DD)
		Next
	
		Return CombineArrays(MD5_WordToHex(a), MD5_WordToHex(b), MD5_WordToHex(c), MD5_WordToHex(d))
	End
	
	Function EncodeBase64:String(b:Int[][], withBreaks:Bool = False)
		' changes this function to use array operations instead of slow string operations
		Local flatArr:int[b.Length * 16]
		'Local b64:String = ""
		Local b64Array:Int[ (Ceil(flatArr.Length / 3.0)) * 4]
		Local b64Index:Int
		Local index:Int
		Local pushIndex:Int
		
		For index = 0 Until b.Length * 16
			flatArr[pushIndex] = b[Floor(Float(index) / 16.0)][index Mod 16]
			pushIndex += 1
		Next
		
		Local baseCharIndex:Int
		
		For index = 0 Until flatArr.Length Step 3
			baseCharIndex = flatArr[index] Shr 2
			'b64 += String.FromChar(base64Chars[baseCharIndex])
			b64Array[b64Index] = base64Chars[baseCharIndex]
			b64Index += 1
		
			If index + 1 >= flatArr.Length
				baseCharIndex = ( (flatArr[index] & 3) Shl 4) | (0 Shr 4)
			Else
				baseCharIndex = ( (flatArr[index] & 3) Shl 4) | (flatArr[index + 1] Shr 4)
			EndIf
			'b64 += String.FromChar(base64Chars[baseCharIndex])
			b64Array[b64Index] = base64Chars[baseCharIndex]
			b64Index += 1
			
			If index + 1 >= flatArr.Length
				'b64 += "="
				b64Array[b64Index] = 61
				b64Index += 1
			Else
				If index + 2 >= flatArr.Length
					baseCharIndex = ( (flatArr[index + 1] & 15) Shl 2) | (0 Shr 6)
				Else
					baseCharIndex = ( (flatArr[index + 1] & 15) Shl 2) | (flatArr[index + 2] Shr 6)
				EndIf
				'b64 += String.FromChar(base64Chars[baseCharIndex])
				b64Array[b64Index] = base64Chars[baseCharIndex]
				b64Index += 1
			EndIf
			
			If index + 2 >= flatArr.Length
				'b64 += "="
				b64Array[b64Index] = 61
				b64Index += 1
			Else
				baseCharIndex = flatArr[index + 2] & 63
				'b64 += String.FromChar(base64Chars[baseCharIndex])
				b64Array[b64Index] = base64Chars[baseCharIndex]
				b64Index += 1
			EndIf
		Next
		
		'OpenSSL is super particular about line breaks
		'Local brokenB64:String = b64[0 .. 64] + "~n"
		'For index = 1 Until Ceil(b64.Length / 64.0)
		'	brokenB64 += b64[index * 64 .. index * 64 + 64]
		'	If Ceil(b64.Length / 64.0) <> index + 1 brokenB64 += "~n"
		'Next
		Local brokenB64Index:Int
		Local brokenB64Count:Int
		Local brokenB64Array:int[b64Array.Length + (b64Array.Length / 64)]
		For index = 0 Until b64Array.Length
			brokenB64Array[brokenB64Index] = b64Array[index]
			brokenB64Count += 1
			brokenB64Index += 1
			
			If brokenB64Count = 64
				If index < b64Array.Length brokenB64Array[brokenB64Index] = 10'~n
				brokenB64Count = 0
				brokenB64Index += 1
			EndIf
		Next

		Return String.FromChars(brokenB64Array)
	End
	
	Function DecodeBase64:Int[] (tempString:String)
		Local index:Int
		
		'remove new line characters and convert to array (without string operations)
		Local tempStringCount:Int
		For index = 0 Until tempString.Length
			If tempString[index] = 10 tempStringCount += 1
		Next
		
		Local tempStringArray:Int[tempString.Length - tempStringCount]
		Local tempStringIndex:Int
		For index = 0 Until tempString.Length
			If tempString[index] <> 10'~n
				tempStringArray[tempStringIndex] = tempString[index]
				tempStringIndex += 1
			EndIf
		Next
		
		Local flatArr:Int[Ceil( (tempStringArray.Length / 4.0)) * 3]
		Local c:Int[4]
		Local pushIndex:int
		
		For index = 0 Until tempStringArray.Length Step 4
			c[0] = base64Lookup[tempStringArray[index]]
			c[1] = base64Lookup[tempStringArray[index + 1]]
			c[2] = base64Lookup[tempStringArray[index + 2]]
			c[3] = base64Lookup[tempStringArray[index + 3]]

			flatArr[pushIndex] = (c[0] Shl 2) | (c[1] Shr 4)
			pushIndex += 1
			
			flatArr[pushIndex] = ( (c[1] & 15) shl 4) | (c[2] shr 2)
			pushIndex += 1
			
			flatArr[pushIndex] = ( (c[2] & 3) shl 6) | c[3]
			pushIndex += 1
		Next
		
		Return flatArr[0 .. flatArr.Length - (flatArr.Length Mod 16)]
	End
	
	Function EncodeUTF8:String(data:String)
		Local bytes:Int[]
		Local count:Int
		Local d:Int
		
		bytes = New Int[data.Length * 6]
		For Local i:Int = 0 Until data.Length
			d = data[i]
			If d >= $4000000
				bytes[count]=$FC|((d Shr 30)&$3)
				bytes[count+1]=$80|((d Shr 24)&$3F)
				bytes[count+2]=$80|((d Shr 18)&$3F)
				bytes[count+3]=$80|((d Shr 12)&$3F)
				bytes[count+4]=$80|((d Shr 6)&$3F)
				bytes[count+5]=$80|(d&$3F)
				count+=6
				Continue
			Endif
			If d<$80
				bytes[count]=d
				count+=1
				Continue
			Endif
			If d<$800
				bytes[count]=$c0|((d Shr 6)&$1F)
				bytes[count+1]=$80|(d&$3F)
				count+=2
				Continue
			Endif
			If d<$10000
				bytes[count]=$E0|((d Shr 12)&$F)
				bytes[count+1]=$80|((d Shr 6)&$3F)
				bytes[count+2]=$80|(d&$3F)
				count+=3
				Continue			
			Endif
			If d<$200000
				bytes[count]=$F0|((d Shr 18)&$7)
				bytes[count+1]=$80|((d Shr 12)&$3F)
				bytes[count+2]=$80|((d Shr 6)&$3F)
				bytes[count+3]=$80|(d&$3F)
				count+=4
				Continue			
			Endif
			If d<$4000000
				bytes[count]=$F8|((d Shr 24)&$3)
				bytes[count+1]=$80|((d Shr 18)&$3F)
				bytes[count+2]=$80|((d Shr 12)&$3F)
				bytes[count+3]=$80|((d Shr 6)&$3F)
				bytes[count+4]=$80|(d&$3F)
				count+=5
				Continue			
			Endif
		Next
		
		Return String.FromChars(bytes.Resize(count))
	End

	Function DecodeUTF8:String(bytes:String)
		Local data:Int[]
		Local in:Int
		Local out:Int
		Local d:Int
		
		data = New Int[bytes.Length]
		
		While in<bytes.Length
			d = bytes[in]
			
			If d&$80=0 		
				in+=1
			Else If d & $E0 = $C0
				If in + 1 > bytes.Length Throw AESException("DecodeUTF8 failed")
				d = ( (d & $1F) Shl 6) | (bytes[in + 1] & $3F)
				in+=2
			Else If d & $F0 = $E0
				If in + 2 > bytes.Length Throw AESException("DecodeUTF8 failed")
				d=((d&$F) Shl 12) | ((bytes[in+1]&$3F)Shl 6) | (bytes[in+2]&$3F)
				in+=3		
			Else If d & $F8 = $F0
				If in + 3 > bytes.Length Throw AESException("DecodeUTF8 failed")
				d=((d&$7) Shl 18) | ((bytes[in+1]&$3F)Shl 12) | ((bytes[in+2]&$3F)Shl 6) | (bytes[in+3]&$3F)
				in+=4			
			Else If d & $FC = $F8
				If in + 4 > bytes.Length Throw AESException("DecodeUTF8 failed")
				d=((d&$3) Shl 24) | ((bytes[in+1]&$3F)Shl 18) | ((bytes[in+2]&$3F)Shl 12) | ((bytes[in+3]&$3F)Shl 6) | (bytes[in+4]&$3F)
				in+=5					
			Else
				If in + 5 > bytes.Length Throw AESException("DecodeUTF8 failed")
				d=((d&$3) Shl 30) | ((bytes[in+1]&$3F)Shl 24) | ((bytes[in+2]&$3F)Shl 18) | ((bytes[in+3]&$3F)Shl 12) | ((bytes[in+4]&$3F)Shl 6) | (bytes[in+5]&$3F)
				in+=6							
			Endif		
			data[out]=d	
			out+=1
		Wend	
		Return String.FromChars(data.Resize(out))
	End Function
	
	'gibberish api
 	Function A2H:string(numArr:Int[])
		Local temp:String
		Local i:Int
		
		For i = 0 Until numArr.Length
			If numArr[i] < 16 temp += "0"
			temp += IntToHex(numArr[i])
		Next
		Return temp
	End

	Function H2A:Int[] (s:string)
		Local temp:Int[Ceil(s.Length / 2.0)]
		For Local index:= 0 Until s.Length Step 2
			temp[index / 2] = HexToInt(s[index .. index + 2])
		Next
		Return temp
	End

	Function S2A:Int[] (s:String, binary:Bool = False)
		Local index:Int

		If binary = False s = EncodeUTF8(s)

		Local temp:Int[s.Length]
		
		For index = 0 Until s.Length
			temp[index] = s[index]
		Next

		Return temp
	End
	
	Function Size:Void(newSize:Int)
		Select newSize
			Case 128
				nr = 10
				nk = 4
			Case 192
				nr = 12
				nk = 6
			Case 256
				nr = 14
				nk = 8
			Default
				Throw New AESException("Invalid Key Size Specified:" + newSize)
		End
	End

	Function ExpandKey:Int[][] (key:Int[])
		'Expects a 1 d number array
		Local w:Int[4 * (nr + 1)][]
		Local temp:Int[4]
		Local index:Int
		Local t:Int
		Local j:Int

		For index = 0 Until nk
			w[index] =[key[4 * index], key[4 * index + 1], key[4 * index + 2], key[4 * index + 3]]
		Next

		For index = nk Until 4 * (nr + 1)
			w[index] = New Int[4]
			
			For t = 0 Until 4
				temp[t] = w[index - 1][t]
			Next
			
			If index Mod nk = 0
				temp = SubWord(RotWord(temp))
				temp[0] = temp[0] ~ rCon[index / nk - 1]
				
			ElseIf nk > 6 And index Mod nk = 4
				temp = SubWord(temp)
			EndIf
			
			For t = 0 Until 4
				w[index][t] = w[index - nk][t] ~ temp[t]
			Next
		Next
		
		Local flat:Int[nr+1][]
		For index = 0 To nr
			flat[index] = New Int[16]
			For j = 0 Until 4
				For t = 0 Until 4
					flat[index][ (j * 4) + t] = w[index * 4 + j][t]
				Next
			Next
		Next
		
		Return flat
	End
	
	Function EncryptBlock:Int[] (block:Int[], words:Int[][])
		decrypt = False
		
		Local state:int[] = AddRoundKey(block, words, 0)
		Local round:Int
		
		For round = 1 Until nr + 1
			state = SubBytes(state)
			state = ShiftRows(state)
			
			If round < nr state = MixColumns(state)
			'last round? don"t MixColumns
			state = AddRoundKey(state, words, round)
		Next

		Return state
	End

	Function DecryptBlock:int[] (block:int[], words:int[][])
		decrypt = True
		
		Local state:Int[] = AddRoundKey(block, words, nr)
		Local round:Int
		
		For round = nr - 1 To 0 Step - 1
			state = ShiftRows(state)
			state = SubBytes(state)
			state = AddRoundKey(state, words, round)
			
			If round > 0 state = MixColumns(state)
			'last round? don"t MixColumns
		Next

		Return state
	End
	
	Function OpenSSLKey:Int[][] (passwordArray:Int[], saltArray:Int[])
		' Number of rounds depends on the SetSize of the AES in use
		' 3 rounds for 256
		'		2 rounds for the key, 1 for the IV
		' 2 rounds for 128
		'		1 round for the key, 1 round for the IV
		' 3 rounds for 192 since it"s not evenly divided by 128 bits
		Local rounds:Int
		If nr >= 12
			rounds = 3
		Else
			rounds = 2
		EndIf
		
		Local md5_hash:Int[rounds][]
		Local result:Int[]
		Local data00:Int[] = CombineArrays(passwordArray, saltArray)
		Local index:Int
		
		md5_hash[0] = EncodeMD5(data00)
		result = CombineArrays(md5_hash[0])

		For index = 1 Until rounds
			md5_hash[index] = EncodeMD5(CombineArrays(md5_hash[index - 1], data00))
			result = CombineArrays(result, md5_hash[index])
		Next
		
		Return[result[0 .. 4 * nk], result[4 * nk .. 4 * nk + 16]] '[key,iv]
	End

	Function RawEncrypt:int[][] (plainText:Int[], key:Int[], iv:Int[])
		'laintext, key and iv as byte arrays
		Local expandedKey:= ExpandKey(key)
		Local numBlocks:Int = Ceil(plainText.Length / 16.0)
		Local realNumBlocks:Int = numBlocks
		
		'CBC OpenSSL padding scheme
		If plainText.Length Mod 16 = 0 realNumBlocks += 1
		
		Local blocks:Int[realNumBlocks][]
		Local index:Int
		Local cipherBlocks:Int[realNumBlocks][]
		
		For index = 0 Until numBlocks
			blocks[index] = PadBlock(plainText[index * 16 .. index * 16 + 16])
		Next
		
		'CBC OpenSSL padding scheme
		If realNumBlocks > numBlocks blocks[realNumBlocks - 1] =[16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
		
		For index = 0 Until realNumBlocks
			If index = 0
				blocks[index] = XORBlocks(blocks[index], iv)
			Else
				blocks[index] = XORBlocks(blocks[index], cipherBlocks[index - 1])
			EndIf
			
			cipherBlocks[index] = EncryptBlock(blocks[index], expandedKey)
		Next
		
		Return cipherBlocks
	End

	Function RawDecrypt:string(cryptArray:Int[], key:Int[], iv:Int[], binary:bool = False)
		'cryptArray, key and iv as byte arrays
		If cryptArray.Length = 0 Return ""
		
		Local expandedKey:= ExpandKey(key)
		Local numBlocks:Int = Ceil(cryptArray.Length / 16.0)
		Local cipherBlocks:Int[numBlocks][]
		Local index:Int
		Local plainBlocks:Int[numBlocks][]
		Local tempString:String = ""
		
		For index = 0 Until numBlocks
			cipherBlocks[index] = cryptArray[index * 16 .. (index + 1) * 16]
		Next
		
		For index = cipherBlocks.Length - 1 To 0 Step - 1
			plainBlocks[index] = DecryptBlock(cipherBlocks[index], expandedKey)

			If index = 0
				plainBlocks[index] = XORBlocks(plainBlocks[index], iv)
			Else
				plainBlocks[index] = XORBlocks(plainBlocks[index], cipherBlocks[index - 1])
			EndIf
		Next
		
		For index = 0 Until numBlocks - 1
			tempString += BlockToString(plainBlocks[index])
		Next
		
		tempString += BlockToString(plainBlocks[index], True)
		
		If binary Return tempString
		Return DecodeUTF8(tempString)
	End
	
	Function Encode:String(tempString:String, pass:String, binary:bool = False)
		'string, password in plainText
		Try
			'[83, 97, 108, 116, 101, 100, 95, 95] Spells out 'Salted__'
			Local salt:Int[] = RandomArray(8)
			Local keyIv:Int[][] = OpenSSLKey(S2A(pass, binary), salt)
			Local saltBlock:Int[] = CombineArrays([83, 97, 108, 116, 101, 100, 95, 95], salt)
			Local tempStringArray:= S2A(tempString, binary)
			Local cipherBlocks:Int[][] = RawEncrypt(tempStringArray, keyIv[0], keyIv[1])
			cipherBlocks = CombineArrays([saltBlock], cipherBlocks)
			Return EncodeBase64(cipherBlocks)
		Catch exception:AESException
		End
		Return ""
	End

	Function Decode:String(tempString:String, pass:string, binary:Bool = False)
		'tempString, password in plainText
		Try
			Local cryptArray:= DecodeBase64(tempString)
			Local salt:= cryptArray[8 .. 16]
			Local pbe:= OpenSSLKey(S2A(pass, binary), salt)
	
			'Take off the Salted__FFeeddcc
			cryptArray = cryptArray[16 .. cryptArray.Length]
			tempString = RawDecrypt(cryptArray, pbe[0], pbe[1], binary)
			Return tempString
		Catch exception:AESException
		End
		Return ""
	End
	
	'helper functions for dealing with arrays
	Function Compare:Bool(array1:Int[], array2:Int[])
		' --- helper function for comparing two int arrays ---
		If array1.Length <> array2.Length Return False
		
		For Local index:= 0 Until array1.Length
			If array1[index] <> array2[index] Return False
		Next
		
		Return True
	End
	
	Function Compare:Bool(string1:String, string2:String)
		' --- helper function for comparing two strings (not required just neat) ---
		Return string1 = string2
	End
	
	Function Debug:Void(array1:Int[])
		Local build:String = "["
		For Local index1:= 0 Until array1.Length
			If index1 > 0 build += ", "
			build += array1[index1]
		Next
		Print build + "]"
	End
	
	Function Debug:Void(name:String, array1:Int[][])
		Local build:String = "["
		For Local index1:= 0 Until array1.Length
			If index1 > 0 build += ", "
			build += "["
			For Local index2:= 0 Until array1[index1].Length
				If index2 > 0 build += ", "
				build += array1[index1][index2]
			Next
			build += "]"
		Next
		Print build + "]"
	End
End