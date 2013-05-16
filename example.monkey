Strict

Import aes
Import mojo

Class MyApp Extends App
	Method OnCreate:Int()
		SetUpdateRate(10)
		
		Try
			' --- FIPS  Verification -----------------------------------------------------
			Print "[FIPS Test Vectors]"
			AES.Size(128)
			Local f128block:= AES.H2A("00112233445566778899aabbccddeeff")
			Local f128ciph:= AES.H2A("69c4e0d86a7b0430d8cdb78070b4c55a")
			Local f128key:= AES.ExpandKey(AES.H2A("000102030405060708090a0b0c0d0e0f"))
			
			If AES.Compare(AES.EncryptBlock(f128block, f128key), f128ciph) And AES.Compare(AES.DecryptBlock(f128ciph, f128key), f128block)
				Print "128 Bit: Passed!"
			Else
				Print "128 Bit: Failed!"
			EndIf
		
			AES.Size(192)
			Local f192block:= AES.H2A("00112233445566778899aabbccddeeff")
			Local f192ciph:= AES.H2A("dda97ca4864cdfe06eaf70a0ec0d7191")
			Local f192key:= AES.ExpandKey(AES.H2A("000102030405060708090a0b0c0d0e0f1011121314151617"))
			If AES.Compare(AES.EncryptBlock(f192block, f192key), f192ciph) And AES.Compare(AES.DecryptBlock(f192ciph, f192key), f192block)
				Print "192 Bit: Passed!"
			Else
				Print "192 Bit: Failed!"
			EndIf
			
			AES.Size(256)
			Local f256block:= AES.H2A("00112233445566778899aabbccddeeff")
			Local f256ciph:= AES.H2A("8ea2b7ca516745bfeafc49904b496089")
			Local f256key:= AES.ExpandKey(AES.H2A("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
			If AES.Compare(AES.EncryptBlock(f256block, f256key), f256ciph) And AES.Compare(AES.DecryptBlock(f256ciph, f256key), f256block)
				Print "256 Bit: Passed!"
			Else
				Print "256 Bit: Failed!"
			EndIf
			
			
			' --- OpenSSL Compat -----------------------------------------------------
			Print ""
			Print "[OpenSSL Compatibility]"
			
			' echo -n "secretsecretsecret" | openssl enc -e -a -aes-128-cbc -K 5e884898da28047151d0e56f8dc62927 -iv 6bbda7892ad344e06c31e64564a69a9a
			' 4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=   Hex: e23fa39ca4d2b13055509f4cb95f211441eec5dc93d3ae6b61b52aa34809a352
			AES.Size(128)	
			Local key:= AES.H2A("5e884898da28047151d0e56f8dc62927") 'sha256 of "password"
			Local iv:= AES.H2A("6bbda7892ad344e06c31e64564a69a9a")
			Local plaintext:= AES.S2A("secretsecretsecret")
			Local openssl:= "4j+jnKTSsTBVUJ9MuV8hFEHuxdyT065rYbUqo0gJo1I=~n"
			Local enc:= AES.RawEncrypt(plaintext, key, iv)
			If AES.Compare(AES.EncodeBase64(enc), openssl)
				Print "128 Bit: Passed!"
			Else
				Print "128 Bit: Failed!"
			EndIf
			
			' echo -n "secretsecretsecret" | openssl enc -e -a -aes-192-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6 -iv 6bbda7892ad344e06c31e64564a69a9a
			' g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=		Hex: 8350fc9df9e9df54c7f23695df7d3828fdb78ba690852694de0b9bc86b55e961
			AES.Size(192)	
			Local password:= AES.H2A("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd6") 'sha256 of "password"
			iv = AES.H2A("6bbda7892ad344e06c31e64564a69a9a")
			plaintext = AES.S2A("secretsecretsecret")
			openssl = "g1D8nfnp31TH8jaV3304KP23i6aQhSaU3gubyGtV6WE=~n"
			enc = AES.RawEncrypt(plaintext, password, iv)
			If AES.Compare(AES.EncodeBase64(enc), openssl)
				Print "192 Bit: Passed!"
			Else
				Print "192 Bit: Failed!"
			EndIf
			
			' echo -n "secretsecretsecret" | openssl enc -e -a -aes-256-cbc -K 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -iv 6bbda7892ad344e06c31e64564a69a9a
			' XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=		Hex: 5d47c321adeead6cb31c2d5b99f9924098da4c45cf98a91062f6c29d877a8056
			AES.Size(256)	
			password = AES.H2A("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8") 'sha256 of "password"
			iv = AES.H2A("6bbda7892ad344e06c31e64564a69a9a")
			plaintext = AES.S2A("secretsecretsecret")
			openssl = "XUfDIa3urWyzHC1bmfmSQJjaTEXPmKkQYvbCnYd6gFY=~n"
			enc = AES.RawEncrypt(plaintext, password, iv)
			If AES.Compare(AES.EncodeBase64(enc), openssl)
				Print "256 Bit: Passed!"
			Else
				Print "256 Bit: Failed!"
			EndIf
			
			
			' --- Decryption -----------------------------------------------------
			Print ""
			Print "[Decryption]"
			AES.Size(128)
			Print "128 Bit: " + AES.Decode("U2FsdGVkX19SF/vHKUf1zS4SMlbROLLCRiyprMJuQ+1nzQJyatGmJhC9xJ6Od+vcZtgZyurEqeEkna1Kj4gqdw==", "pass")
			AES.Size(192)
			Print "192 Bit: " + AES.Decode("U2FsdGVkX18EDbSr5+mGnFZRUwSTISFzadp7wsC/kTgtco+fQ4hMMrJ1zpePN6sicBnAOaC+p/vCmgb3zBc7Ag==", "pass")
			AES.Size(256)
			Print "256 Bit: " + AES.Decode("U2FsdGVkX1+f4uMd56OoVkwmaLStldQEHRNSGa1gRVF0XUvNNIr4Vg1PWa+0HHpiTRmvKXFSY90SrJea4Cb+zA==", "pass")
			
			
			' --- PBE Testing -----------------------------------------------------
			Print ""
			Print "[PBE Key IV Test]"
			AES.Size(128)
			password = AES.S2A("mumstheword")
			Local salt:= AES.H2A("C3CA5EE98B8F1FC5")
			key = AES.H2A("1D189274EB848A8CD1F3D029030E0E5A")
			iv = AES.H2A("ED562A01653B3973C4507CF2B97F3641")
			Local pbe:= AES.OpenSSLKey(password, salt)
			AES.A2H(pbe[0])
			AES.A2H(pbe[1])
			If AES.Compare(AES.A2H(pbe[0]), AES.A2H(key)) And AES.Compare(AES.A2H(pbe[1]), AES.A2H(iv))
				Print "128 Bit: Passed!"
			Else
				Print "128 Bit: Failed!"
			EndIf
			
			AES.Size(192)
			password = AES.S2A("mumstheword")
			salt = AES.H2A("6C96EB8089668585")
			key = AES.H2A("1A5EC3EB94BF5A675B2CE79E30D84EA8E68936A7E17FFCC7")
			iv = AES.H2A("6E82636638721A2C7B92FB6EE007C3BC")
			pbe = AES.OpenSSLKey(password, salt)
			AES.A2H(pbe[0])
			AES.A2H(pbe[1])
			If AES.Compare(AES.A2H(pbe[0]), AES.A2H(key)) And AES.Compare(AES.A2H(pbe[1]), AES.A2H(iv))
				Print "192 Bit: Passed!"
			Else
				Print "192 Bit: Failed!"
			EndIf
			
			AES.Size(256)
			password = AES.S2A("mumstheword")
			salt = AES.H2A("5F934E4432AEB8B3")
			key = AES.H2A("3d6b59e8c5623ce4ff7c165995b209e7f03461ec057ca33a5cd1559d01e5682b")
			iv = AES.H2A("5be59eadbed053db61bd9e413fb8b7d5")
			pbe = AES.OpenSSLKey(password, salt)
			AES.A2H(pbe[0])
			AES.A2H(pbe[1])
			If AES.Compare(AES.A2H(pbe[0]), AES.A2H(key)) And AES.Compare(AES.A2H(pbe[1]), AES.A2H(iv))
				Print "256 Bit: Passed!"
			Else
				Print "256 Bit: Failed!"
			EndIf
			
			
			' --- UTF-8 Verify -----------------------------------------------------
			Print ""
			Print "[UTF-8]"
			AES.Size(128)
			Local chinese:= "ç‰ˆé¢å˜åŒ–"
			Local encString:String = AES.Encode(chinese, "secret")
			Local dec:= AES.Decode(encString, "secret")
			Print "128 Bit Before: " + chinese
			Print "128 Bit After: " + dec
			
			AES.Size(192)
			chinese = "ç‰ˆé¢å˜åŒ–"
			encString = AES.Encode(chinese, "secret")
			dec = AES.Decode(encString, "secret")
			Print "192 Bit Before: " + chinese
			Print "192 Bit After: " + dec
			
			AES.Size(256)	
			chinese = "ç‰ˆé¢å˜åŒ–"
			encString = AES.Encode(chinese, "secret")
			dec = AES.Decode(encString, "secret")
			Print "256 Bit Before: " + chinese
			Print "256 Bit After: " + dec
			
			' --- Benchmark -----------------------------------------------------
			Print ""
			Print "[Benchmarks]"
			Local startTime:Int
			Local endTime:Int
			
			AES.Size(256)
			Local text:= "Something small to encode, lets hope it's quite quick"
			startTime = Millisecs()
			For Local i:= 0 Until 100
				AES.Encode(text, "secret")
			Next
			
			endTime = Millisecs()
			Print "100 Encrypts: " + ( (endTime - startTime) / 1000) + " seconds"
			
			Local crypt:= "U2FsdGVkX1+qbsRBKWqv3Hs8F187/SvIivffz/8tosmb4JocDocxBSTxAIWn1KkzlBRcIdYnlOKhgyJboCHn5SvQw+CDc/RLy2UIKGV2LpI="
			startTime = Millisecs()
			For Local i:= 0 Until 100
				AES.Decode(crypt, "secret")
			Next
			endTime = Millisecs()
			Print "100 Decrypts: " + ( (endTime - startTime) / 1000) + " seconds"
			
			Local bigtext:= "Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Etiam volutpat. Sed rhoncus mauris. Proin pellentesque felis in est. Vestibulum bibendum. Etiam nec augue id justo congue interdum. Sed magna. Praesent ac enim. Fusce tempor nibh a elit. Maecenas eget sem nec pede posuere aliquet. Duis ut dolor at purus eleifend sodales. Nulla bibendum volutpat lectus. Suspendisse potenti. Morbi tortor risus, semper a, faucibus nec, lacinia eu, lacus. Integer eros orci, semper quis, congue vitae, lobortis sed, nisl. Nulla sagittis lorem eget velit. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae Sed facilisis ante nec lacus. Maecenas et tortor. Sed eleifend orci vel elit. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Sed dolor magna, dapibus id, malesuada vel, luctus non, enim. Etiam pretium nibh quis nunc. Proin egestas nibh nec diam. Proin tellus nisi, tincidunt ac, eleifend ac, aliquet id, tortor. Integer luctus pharetra massa. Nulla facilisi. Sed ante odio, euismod eu, adipiscing id, luctus sit amet, nunc. Vivamus odio. Donec congue orci a felis. Duis lacinia, odio sed tincidunt rhoncus, augue magna tempus magna, ut feugiat felis dui ut odio. Phasellus cursus sapien vitae nulla. Nunc urna. Aliquam dapibus enim sed neque. In ornare luctus nunc. Sed augue neque, luctus sit amet, feugiat vitae, varius at, metus. Donec tellus est, pulvinar ut, faucibus eu, imperdiet vitae, nibh. Donec quis sem id sem sodales interdum. Vivamus eget velit. Fusce convallis mi ac est. Suspendisse justo. Morbi eu neque. Nullam non lacus. Fusce lobortis. Aenean dignissim ligula quis erat lacinia ornare. Nunc accumsan, velit at ultrices tincidunt, enim libero adipiscing sem, eu tempor mauris erat tempor massa. Duis nibh est, tempus a, pretium at, tempor at, dui. Pellentesque erat purus, viverra a, porttitor at, vulputate ut, enim. Aliquam et nisi. Nam ultrices. Donec ut lorem. Nam accumsan magna vitae risus eleifend lobortis. Fusce metus velit, luctus vel, dictum quis, fringilla id, nisi. Aenean et lectus a eros viverra vehicula. Nulla imperdiet laoreet velit. Quisque et est vitae felis commodo lacinia. Etiam bibendum risus. Maecenas lorem risus, porta ac, viverra rutrum, ultrices nec, purus. Phasellus sagittis accumsan elit. Nam venenatis, magna non pretium eleifend, massa eros hendrerit libero, at ultricies dui quam venenatis ante. Ut ultricies tristique dui. Donec volutpat dignissim diam. Maecenas vel massa eget nibh malesuada fermentum. Pellentesque lacinia. In eget est. Vestibulum vel nibh. Sed scelerisque risus et tortor. Phasellus hendrerit. Duis nec erat sed justo vestibulum pretium. Cras rhoncus mollis nisi. Proin rutrum. Morbi lorem. Proin ut felis faucibus pede cursus elementum. Donec dui. Nam nec nisl. Praesent tincidunt massa. Morbi dapibus interdum urna. Duis consectetuer. Fusce quam tortor, consectetuer at, ultricies sed, lacinia quis, diam. Maecenas nisl. Vestibulum auctor fringilla diam. Vestibulum tortor augue, lacinia sed, viverra nec, porta vitae, quam. Nunc sagittis porttitor risus. Integer justo. Integer sagittis, quam eget fermentum vulputate, ante felis lacinia turpis, vitae scelerisque magna erat eget enim. Nunc rhoncus libero vitae erat. Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aliquam id arcu in metus tincidunt accumsan. In hac habitasse platea dictumst. Proin mauris. Cras mollis urna at ante. Nullam non dolor. Nulla blandit. Vivamus vel urna ac erat pulvinar volutpat. Nullam porttitor. Nunc vel mauris. Aliquam velit. In tempor, ipsum vestibulum aliquet viverra, felis odio lobortis sapien, at dapibus est libero venenatis felis. Nulla bibendum sodales leo. In in nisl. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Pellentesque bibendum, sapien vitae posuere pulvinar, nisl lorem cursus orci, id porta leo arcu ut nisl. Cras nisi nisi, posuere elementum, porttitor ac, porttitor a, dolor. Integer nullam. Nullam porttitor. Nunc vel mauris. Aliquam velit.Nullam porttitor. Nunc vel mauris. Nunc"
			startTime = Millisecs()
			Local bigcrypt:String = ""
			For Local i:= 0 Until 1
				bigcrypt = AES.Encode(bigtext, "secret")
			Next
			endTime = Millisecs()
			Print "5 Big Encodes(4k): " + ( (endTime - startTime) / 1000) + " seconds"
			
			startTime = Millisecs()
			For Local i:= 0 Until 5
				AES.Decode(bigcrypt, "secret")
			Next
			endTime = Millisecs()
			Print "5 Big Decodes(4k): " + ( (endTime - startTime) / 1000) + " seconds"
			
		Catch ex:AESException
			Print "Exception: " + ex.message
		End
		
		'return something because of strict mode
		Return 0
	End
	
	Method OnRender:Int()
		' --- the app is rendering ---
		Cls(Rnd(0, 255), Rnd(0, 255), Rnd(0, 255))
		
		'return something because of strict mode
		Return 0
	End
End

Function Main:Int()
	'put in big try/catch so we can account for errors
	New MyApp
	
	'return something because of strict mode
	Return 0
End