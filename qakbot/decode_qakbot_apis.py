"""
    Name        : Qakbot decode apis string
    Author      : Charles Lomboni
    Description : Binary Ninja plugin to decode strings from Qakbot sample
"""

xor_position = "3B7397BE28A1C5F978B59AB2051D03958DF21305135685E5460321F2A9E6606065A8F68BE82962667C5FEB26A23B607EA9220EA63E6F5F043DF1ECACB21F1869"
heap_allocate = "6B21C8EC4DC0A1F930C1EEC2447967C7E88366606022CD8027674480DAA760230AC682EE865D4F32052F8E1C825A100EC54B6DC74A06306A1289C1DBC568350F5401FA935DD3A99C16D6F5D6607903F6B7AE7B6C7133F7832F6F0F81D095131365EB84EE895D0735192D9D4FC15E377EEA477CD26D0A2B47588398C5D4767B084F16D4D146D5A0810CE5E8DD757871E1F4F223352356F0972A6E4E9C87820C0C6588D9CDE87D1007122C8747D65E2D1BDA516FC15B6F3A7C5E9D99C8D7406D1B5773C7DF5CC988980CD6F2E1757860D48DB676766724EA9C116A4F96C69160360CDA82FE8945230A10308863DA3B0D12DE5051D5531F33047E949ED8F173771A5E20E3D15AC4C5A52BCCE9C6607030A7D1A57A6B7739F296166C5697DBB5080509C4AAFDD907523A0C309C43D048081BC54E20C3460A5F474F948DD8D75B711B5E10E3D15AD884F90FDCF4DB6B7877BBE99E7F055E39E1902A6612C0E7831814658DB4C4BC762F273F17A268E764352BE0662BA61B2D105062A7A9E2F6504A367237B2BE5ECCB7980FD1E9D9054F66F2C282766B5833FCA03E4221BBC79205120BCD82D88D5D2D1608368448E33B321BCE6162C94D0A146144F1A2D8F16D7D084F16C4DB4BD5AC9616B5D4C6556F6CE1E89167537A24F190276F6C97C489121965E693FFAF4C162C1336856FCC5D0F0CC4437ACF51015F56589685DFC67A6A2A5712E4CD6DD984F90D849AFF606E70F4EA97516A6B1785B212507087CC94193516CD84DF874207087C1C8749D15E331BDB5467C55B273E6A599D89ACD17076075E10E3BE49D1B59511D6FBC66C726DBAF5DF606D7C35EE92277544DFCF8A01130DA8A5C4AE7D35272E1AB771CD4C564A9A1040C95A0A034954929EC3C1707E1D6724FED04CCEB28A58F1FFD4607367F0FFAE40756A38E0914626728BDA92050D37C799FFCD75311F0F2B8E4B91093C13C6407DDF500C71614594ECE5DC6B7D1B5516E3F94DD5869617DEF3D7441D51F0EAA36660612FCC8B206C6A97D0A7602109C499E8895D0727123BA248CB4F091FC54B74C36D063B04539498DFC67E6C49161DF6D128E8AB8D1DC7F4D7715273F0E3B3134D6722F5AA36664FA0CC97150516DCB78BAD47170B2B368542CD4C137EDC516BD40D5D7160519DECC8D36B79365A15E3DB5AA193BB17CDDDC7606E7795EC81646D7C39EE8468674D9EA9B4050101F884E48B4C1115313A8649D042603AC7515FD35B1D265B7CF1B1A6B2516C2E5E07D4D146D5A0810CE1F2C0607C6795E99367644C33EB8146744C9BCAC610120ACB93F89B0901071033CB45D05E010ACC0229C3461F3E6A59D1CE89E13D384B1E20B59922A195AB27E2E8DB717803CFFAA07676663BE0B12E714493CDE60E1009A8B1EE9C6A17140E3A8552F653121BC84647C23E4A0C7D4E8589C1E070771D1E2FC4C75BD5A0944B87C6CA727479F4FF963D606B3385862E714E9FCCB903080CC492A58C450E6615328A41C7140717CF2258EB490E2D611D8289DEC47A6A495616FAD15AD8C5D91BDAF5D96C783ECEA8814E056038FD8D2D5C439DDB8205123AC58FFC864D62350C26A543D669050EC6507ACF50085F474F889CD8F37C691C5201F2FD4DD3B1901EDCF9D3717853E7E4847271761DE09C464A4F86CC940E0511FB93FFBB5D0312092CA847CE57021FCA490EF571290B537CA3A9F0FF767B1B5400F8D85CFD929016D1F5C5764140E0FF80766B6700E097356A4E9CF5B4150E65DE9DE29B4C4C03043AD04FD15E130CDF0C6BDE5B543C6959908BC9DC6B360C431697E865D6A48B1D95CCDB76696295E0C31357673ACB9115774086DC95340F21C785CE9A5B0D147C289F55C34B094D9B0C6ACA526F3C6C4F9E81C99C7B74053B3EFEDD5ACEB6961EC1DFD662782DF0F59713427622C6892F73439DC894042404DC978BAF4C16330E33A847C153053BC7567CDF7701396B6AF1B3C8D77C6A104B07F2DA06C7AC951D8ED7C769696AD4E3937F7C603FF6BA30036297DB92270511E697E68D7A161415318C71A268141FDB565DC34C19366758A6ECDADF6B77065700F3904DD9A0F92EF8EDD3777823C6DBB552056033F1903662519B87820C0C65F8A4D4AB450D15195FA248D65E1210CC565FD35B1D26405C858DEDC47E71055A11FBDB28F183A13DCDEADD776940F0FF8640717C24E0E53774489CDA92016001C982EAB74B0700132D8E26F25A1416E4437AC5563C2F615EA6ECEFD76D6C285F17D4EA64E2AA970CD0E2C6517250E1E28076053606F78A2171409FEF8F0C0516808EB3DE00473A35319F43D055050A896776D652002D614FAD85C9CA6F74064916B9DB50C4C5AA37F3CEE5444F46C9C09B70777C25EA83325F769BC7820F171688B2EE8E4C0C02192DB775D2422E1BDD225DE7682E3B69549FBFC9C069710A5E5DF2C64D9A96980EE6FFC0737460F0A3976B60133FE28B297144ADDC940C600CD895E4864F0B015C708A4ACE3B330ADB6163D677385F56499DBFC9C653791A4F24FED01B93808B0ADAE8B256786FF3AD8676766776C3A40F4F64B688C741602CC682EE9A4707123B3A9F65CD540B17CC6776E73E413B6549F1BBE2D76B57195E1DD2D05DCC92F91BDAE8D7567871E3E49176567B33E9896866599792B603032BFCBBE48607071E1964A572F06F331DC84C20C3460A5F57589F88E1D76C6B085C16D6BE4BD2A68B11C5EE9C60656695BFC13D312A78B4D6683012C89ED6505065C693FF9C4C0E0A192DC545CD566030DD6F6FD668063A737297BFC9D16B71065573C0F04DD5869816D6FFDE46726DFBE891676C7C38B7B246514495ED830C0511CDA0EA845C07277C128450C77D0912CC630ED5560328654D98C2C8DE73181F5640F3D358A1A6941C95B5D1256E60FDF993606E6078E09D23230EA3DC8312194596D6A9CD5A40661F328F08C743057EC7517D95100B33683DBD88DEF57A6C39491CF4DB4CD4B79C39D1FEC0606E7095FA97716C7D3CE08632700F91CBE62D2224E5A5EE9A5F0B0519718E5EC7000D1CC84F69D357413A7C58F1AFDED77E6C0C6B01F8DD4DD2B6B016C1FFC06B7C6FC28D8670757723E895686659979291090E01DD9BFBC64C1A03473A9F4EC749051FC50C6BDE5B54286D4F949FC4D36D73475E0BF2854DD5B19C0AD6FBC22B787BF0B68067767D3FE38368665997929601030ECD82E8895916130E3AC543DA5E5B1DC8527AD34C0A316149DF89D4D71F3D1A1B56A78A508FE08C5890AA867D3326E0AD8076762976A0966670449AF69205131192D6AE9D090109122C9F55FD4F050DDD182E835A4F2969599498C9D16B7D0D0153B2DA08C2B79C19C1FFC2777260F0FE812925363285AB3254539BDD83360917DC83EA8464070B132D9226ED4B0510F95061C55B1C2C040FF1BDD9D76D612F4E1FFBEE5ACEA69C0BC6D3DF647A66DBEC9F76521315D2B6276D4590C69E60360CDA82FE8945422E385FBB75D654121BEA506BC74A0A166A4E858DC2D17A18085910F3DB4EC6AD9012DEF6DF6B7273E4FF8167706521FD9C3C03019AC695145D3E8D85B1CD5C3F46092C8E549F60450DF4027EC74D1C625F1882B1A1B81F4F3D6822E2DB5AD8969C0BC6F3DD6B546DF3E2807E64673FEA8B1103479BDB83060F1D8693F38D294849565FCE75DB48141BC47061C94A4A03574482BBE3E5292C355E0BE7D247D3A08B56D0E2D7057577E1FD81292A3C33EBCB316A4A9BD9830409048699F98F0611121D2B82458D5A100EC54723D2511A3C6C128685C7DB6F7D0D5212B9CE46C6C5BA1DC7EEF76B686EC6F48167607E05F18A3466219CCC9201100C9BC4A58C450E663F2D9256D67E0E0BC46D47E27701396B3DB998D8C24E6D0C490ADED04ECE92F92BC0F8DF6C6950F4E0827F606015EA8B35664F86A9B505142BC99BEE8C7A0705092D8252DB720E18C6630EE7480E2C706E878F82D7677D697A37DAF76685C5DB5DC6C6C17C6E77F0E0C121596035ED9127704A81878318054788D9CFAD652732397FC4608214343089077DA66C0A3841538481FAD3736D0C7A73C0ED69E2AA9716D0F9C6057370F9E29D78706376A8943366538BDD9F100558E9BAC7C804160F113A8453D606514E897D62C25F1F715B49929C82D67C36365600F3DD5B8FE08A78E5FFD76E5066E6FE9374605256C69723625597EF8F0C0532A8B5F98D4816033A368743E33B514C9A163B90095766343DDF88C0DE1F71583B3FF8D143D4B5B81BD6F5C76B6950FCE9B313646126A5C8270310C09ACA100116DB81E49A4D4E361D2C9851CD490452C5477ACB5B0631280CC3DF989E2E2A5A0F46BB8F1A92F1CC4E99AB80362936A3BADE22372062B0D3713B0DC39BD55455539FCEB2C4185055486ADD119A025052D8556BD44A16736852878980DB73771F5E0AF8CB04D1B79016D6FFC1763173E0FE816A297E37F69123710D9FC6880B051C8497E98B1850555066D21F9B025947900E379F0756663D04DDD5958B262150174AAE871198E9C0418CA39E3C243AB9B4CB3F3C3F6EBDDD7E3B19CA91CA58585D90CEB3D0055A5E4467D31E8E035846911A229E0657672805C9D4808A2734511744A0891F96F2CE4F99AD85322A34A2BADE24322461B2D26A3416C59ED14C57529FC1A7DF1E554A4B68C7118E0D56489F143890084369320BC7DA9A84332E5F0D45A1880497F3CF4E83B684332B35B9BBC425292560A9D36A3614C79CD355555084C3BEDD1C57534973DE13970E554B85173B930B5A733108C4D980872A2D450E46BB8B0495F1CD4C81AE86313137A1B9C62731277AB1D1723715C685D25454519CDABFDC1D564A486BDF0A960F4C4A85113D950D5C6C370EDDDF9F812C2B5A085FA48D1B92F6CA5486A981362E2FA6BEC120292065B6C975300DC185D45252579AC4B9DA0550544E6DD9149017524C9B103C94125D6D360FC3C09E802D2A450941A5921A93E9CB5484AB83342C32A4BCDE22342267B4D4772F10C398D751514999C7BAD9184E574D6EDA0A930A515298132297125F6F340DC1DC9C823328590B43A78E188DF5C94885AA9E352D33A5A1C223353F66B5C9763A19C59FD354535799DAB2D01E5453486CD9178E0357489C163D940F43683208C5DF9E83332E5C0F40A58F0494F1CA4A84B686362F32B9BEC022292167A9D4742F5287D983124C16CD95F98D5D4E15192D9D43D0170311C4527BD25B1D736B4A9F89DE9E7D790A5006E7924CC0B1981AD4E9D729716CE1F8813F6A6137E689232F4387DA8F0E0516DBDAE689470301192DC752C7561011DB437CDF120637654B9482C3C27E6B1A171DF8CA40C8AB9E54DBF5C2646E70E2E28077297D39F58435700DBBC79205120BCD82A7814716030E318E528E5E181FC45262C3121C3E694D9D8980DE706E0C0A41A4924ACEB68A4987A99E727271FEBCC020297B39E880773112DEC49F1003549AC5A79C4C0F164D6DD80AD65E130A98103D8A4F183A350FC2C0DCC52E2A5A1701F8D15C90F7CA54C5FBC1762C31A6A18272766067B7C93662528198CA010408C198BADA1A4E071832824893094C1FCD4F67C80F432F654E829BC3C07B295B085FE7DF5BD2B2960AD1AB80296D62E6FE857C777767A98123654087C5924C060AC794EA9A050409133984498E4F0513D9566BCB4E432B615081C0D8D76C6C1D5E00E3925CC4B68D54C7F5DD716F6CFAF9DE616A7C22A98333604ADED39C1A1A1F848CF192534E1C0625C75EDA431806855A76DE4643277C45DD9DDDC36E69454A02E6CF04D0B48854D4FBD3647C2FF4EC9372297237E4C935724DDECF8F0C0549DF93E9C44F0D09503584448E530F13CC0E79C94C04736D53859ECDDC7A6C45581CF9CA5ACEA9951DC7B6D96C716FF0FFDE74647E33F6C936714884C892054C08C984E08D5D4E0513398D43C7170311C64967C312093076588789DE9E796A0C5E17F8D304D2B18C1CD0F4C6297C60F6E2877D713F37E68422664C9BC8CA060909CD85A79F400C021328980ACF540E17DD4D7C8A4B01346A52868280D371611D531AF9D904CDA08D11C1F8D729796CF8EC9B7D297235E68035700D9FC688051949CB97E6985C114A19279B4ACD49050C854776C5560E316358DD8FD9C16B77045E01BBDD44D4B68D1DC7B6DC6A7F6CF1F4DE706A7733F28A34670D91C682050E04C593A78B4103081B3A86438E5F050DC25661D6121C3A67488385D8CB336B0C5806E5DB04D1B09B14DCF99E766470E1E89F3F767B37E18A312F4E94CF8F030549DB83FB8D5B140F0F30990AD14E101BDB577DC34C432C6C5C838980D37B75005512F3D341CFE99401C5FBC1766A6CE7E9DE7E7C6337F6966A734081DACA2C0F02C198A78446050F12739B47D148171A855876C5480D312847898FDAD03362115810EFC404DBBD9A00CFB6C3646774E6F59777663F27E49F317059DED8D71752009BDAFA9F4C0315182593458E5A131ACF45668A5F1C3B7E4592C0CDC17B7C1A5A5FF6CD4CD2A4D509C2FFD376792FE4FA977672627AF492237450DEC78F0D04048497EF85400C0F0F2B9947D6541252E84663CF50433E6050988280D32E7A5B5840BB8F5993B2CA1D99AB80362972E2E8803F342165B184246045DE98D4530116CCDABADA1A13111973DA14915A021D85133C950D5D6E280CC3DF9E8333295B0842A58D04EBA4941DC6B6F86A756DB9DF9D71606122A9A82F604993CC8A4C370CC49AE289444E221D2982428E69091DC1437CC2122C37654F9D89DF9E55771A5E03FF927CC9AA9419C6B6F16D6F6AE6F99D636D7624A9A1276D4897C5CA300110C4DAC6895B094A38308547CE5F4C39CC4D7CC15B431461539F89D8DA334B1D5E05F2D004E4A18E19C7FE9E476F6AF4E3DE416A7D37E9816A424F86C1890E1949E393FD81474E2B1D2D920AF25A140CC04167C71223366A5990C0EED36D7A084912BBFB44C8BF981AD0EEDA295766FBE39B7560617AC884346A40DEFA9313010B84BBEA9A4E0314192BC762CD490F0AC15B22EA571C3E28739082CFCB3353084916F9926AC4B18D0199D2D769786DB9DE937D616137A9A1296D4F9385A501120AC4DAE1894407155035844ECC171211CB477CD212023667559089C09E687105571AF6D304C5A48F11D1B6C06C7E6BF4FF963F667B37F78923700D98C69505100D8482E387440315503C8354CB481411D94A6BD4120B3E6A54948080C27E6D05171EF6CC438DA19616D4F6D6297A66FAFF9576297833EB8B237749DEDA92051600C6DAEE8C5E031418738954CB5A0E52DB4D60C7520B7365538584C3DC6634025E05FED004CCA48B0199EAD3716F6AF6E4933F697A38E1846A614080CB87120149CD9AE2924800030837C74CC7550E17CF477C8A530E2D6D5CDD9FD9C17E76455612E5D949D3A08D54D1F5C06A696BECA19E7A76727AEB84286058DEC28712050B8494EE9C5D1B4A143A8743CC17131FC7467CC7120B306A5390C0CFD36D77051711F6CD4DC3A4951499FEC0647A6CFBA1947C6A6734E4892A2F4C87DA92010E028485FE984C100B1D31C7109B0D5948900E6CC74A023E6A11859ED9C16B76060A73C4DB5CEDA48A0CF0E8C06A6F03C2C39767447732C68A286D4491DD8F0F0E57FFF6B8D811620E082B9B5598144F7ED2073E94664A6F3665D4DC9EEA3A285B635EB28E1AF9E0C94AEDB797352F5BB0BDC04B283666B7BD633313AA84C350523D8DC6B9B00C5254247ADB14FA1E504CF1073E9466125F474F889CD8F476760D743AD3F746C7AAF93FD0EEFF606E70F4EA974405503AEA96234B409CCD8A05600699F6AE9B75111F0F2B8E4B91093C7EFB476FC2780633613DBF89D8E177791B5E36F9CB45A1958B17D3F3DE60546EF4EA974364673E8596236D45F2898318143AC186B6B30C113B5C3B8555CC5A0D1B94792BD5634F376B4E8582CDDF7A25321E00CA9E5DD2A08B45EEBFE1583D67FAE0937A6B2E0DA0B61B234881F687040D0CC6CBD0CD5A3F46132CD67D87483D5ED84061D261193A764E9883C28F443D1A6653FED05BD5A49514EAEEDB68783ECEA8814E25762EE0D81D2672AF8996120F01F79FEFD5724715215FBB74FD7C050AEC507CC94C6F377049819F969D307B0D555DE4CE4DC4A1961E9BF7D72A6E62F8FD9E7631236FB38E6861489C96945D504B8D838BBB4C1646133D8171EF72331BDB5467C55B4F62247A9498E3D0757D0A4F5BB5C941CFA89E15C1E988273D25B5AF897A686333F796296D4086C0890E2C00DE93E7D5400F16192D9849CC5A141BD40352FA10337A67529E98F0D176751F0951BEB47BC4B1D917D7F0E2777260F0FE8133383311E09109614B97CA92484212C198E68F441615462D8449D6670317C4543C9C690631370FAEBCDEDD7C7D1A4851BEB44DD3B7AB1DC1EFC06B3D3EB5E29079556139E68035700FB1DB8301140080D4AE9B0B4E46122A874A8E1B0E0BC50E2EC84B0376047385BBDEDB6B7D3F5201E3CB49CD889C15DAE8CB055377C2E28525314133E481106A5386DC870C2D00C599F9911F56660D3D8452FD580F10CF7D7EC74A07622318A2CB8CC76C7D1B5512FADB1586E0AA5F959A9C667B6495C58667754033EB8114665087CC95143765F897FF806A0D0B1E368543F53B231BDB5649C34A2C3A7649988AC5D17E6C0C781BF6D746A1AB8909B5DED7697877F0DE9761737A35E0B246506EB4FDB1213220F4BBE28B5B0D1513399F7AEB55141BDB4C6BD21E2A2774519E9EC9C0435B065F16DED05CC4A28B11C1E3B2687877E6FB913E767624F380342D448ACCE6231200C982EEB85B0D05192C9867D16E131BDB750EC75F0D3C6058948ACBDA767103501FFAD047CEB5880AC6EEC7706B74EDF48B69053379F790662103F2FB83072317CD97FF8D62071F3927AA26E1013C22E06C5AE36C211E4861ADB3F3D772681D4273E4CC47CEB19211C19AF560694EFAE9877F605B37EB812A6660F2FEB5213300DCBAEA9B5D27140E309926EC4F3711DE143AF74B0A2D7D749F8AC3C072791D521CF9EE5ACEA69C0BC6AC86054E6BF0E19E567D7635F091235421A1CC92250E11DA9FEE9B600C271F33AA26EC4F260CCC4758CF4C1B2A6551BC89C1DD6D61697D1AF3DA44C4B7D71DCDFF89767C6EE5BC973D606B33BE96276E519ECCC80518009384FE865A030B0C338E08C7430545C54D7CC24E0A71614594D7DED7786B015407B9DB50C4FEB80DC1F5C0707370BBE88A763E7725EB8C20650F97D1835B3627C78EDF9A481B4819278E1DEA5A1316E45B48CF520A2C2A58898997E26D770A5E00E4F649C2AE9C0A9BFFCA602653E7E2917E6A7D78E09D23387180C6850D0F0B9EC2A58D51075D123A9F4BCD554E1BD14735D0531B306B51828882D7677D524D1EA4DA5BC4B78F11D6FF9C606566AEDBB55270673ED68034754891CCC80518009386F9D84A511E0C718E5EC700300CC6416BD54D273E6756949E82D7677D527835D19E6DD9B59517C7FFC02B787BF0B69666686335E4956866599792B1091200DB9EEA9A424C03043AD04FC65A1150CC5A6B9D570B3E750BC5C2C9CA7A233D6B32E2CA47E2AA9716D0F9C62B787BF0B6A076767C23F786234B4091C283124E00D093B09E440305083787568C5E181B926D42EA672B1D4313B4B4E9896871075F11F0904DD9A0C21AD1E99F737470FCE29C3E647433EB916B6D409B878318055ECA92F8C55F0B151530850BC34B090D874776C3050D3B77108785DFDB7076445A14F2D05C8CA489089BFFCA60264EE0E1867A447D37E99C356A52ADDFD74E504B9ACFBFC64C1A034727D814C6590750CC5A6B9D682D307C69838DD59C7A600C0025D5D150F2A08B0EDCF9D72B787BF0B6A67075653FE09268665997A985121915DC83E2C64D0E0A7C3A9954CD49400CCC5133811B1C782458839E91977B38055E1DAA9B5DA1A08108D9F5C0606F2DF0F597136B7622F68D66624584CF8F120512C99AE7C84F0B1419288A4ACE1B011ACD027CD3520A7F6A5C9C8991903A6B4B1B17FECC15C8ABD919D6EEDB6A733EF4E19E7C723326F78A2171409F94C44513478893E5894B0E0341268E55A275142FDC477CDF68062D70489080E1D772771B4273E0D647C0A890589AFBDE691D60E7F48267362178E1892A030187DB8A5D3B40DBABAB8C4816074104CE55FF366A7EE04C67D2570E336D479882CB927B791D5A11F6CD4D8FEBD778F2FFC6487267E0E197556C7F33CB842B6660F2C3AE180116DCB2E88C5A4B09313CD64CD4535709CD7766DE5D1C3B700FF1BAC5C06B6D085723E5D15CC4A68D3DCD9AFC606954FEFE8672427622CC8B206C2193DF81031317DE8EA58D51075D1D298C55D4581850CC5A6B9D5F1938674E839ACD9C7A600C3B3DE3EB46CCA4892EDCFFC54A7B50F0EE867A6A7D56E497326A4793CA924E051DCDF6FD8548011214339B08C743057EDA407ACF4D072B046F909CDCDD6D6C2E6B5DD3F264A1979C1FE4EFD7776455F4E18776406B1785A6346645B7C7930D0517C982EEA929260F0F2F8A52C1532D1BDA516FC15B2E5F53549F88C3C56C29591B36F3D94D818D8D0CC5CBC7606F7ADCE3947C255123E2C4672221B18DE621040FDD85FFBC460903120F994FD4520C1BCE477DA67D0A2D70728189C2E16B771B5E73DED05CC4B7971DC1C8D7647945FCE197567D5256D6872F66659EC5C8040C09A8A5C4AE7D35272E1AB76BCB581211DA4D68D2622236674F9E9FC3D46B38285507FEF349CDB2980AD0C6E175644DF0F9F27D696733F691662C459DC487090E3ADC84FE9B5D1146533E874AFD4F120BDA567DA66D0A2B42549D89FFD77C6D1B5207EEE928F3A09E2BD0EEE4647176F0C88A52053605FC9632664CA0C689144539FB8FF8BF66355048039351CB41010CCD0C6BDE5B6F3977559E9FD8D76D2B5B1516EFDB28F7888E19C7FF92565E50DC8DBA67716305E08B22514483DC83131420D0A18BBE401012093E8776D054141BCA560EF557153A6B5BA389DFDD6A6A0A5E73DED05CC4B7971DC1CBC7606F7ADAFD867A6A7D0185B30B4274B6E0A960170CC692E98F07071E1964A84ED0540D1BFC526AC74A0A71614594D7C1C17B7D1F1516EFDB13C5A79E0EDCFFC52B787BF0B69D7F696A32E782686659979285140608C798A58D51075D2C2D845ECB5D091BDB0C6BDE5B5431654BDF89D4D72455005801F8CD47C7B1D736DAEED7763366EDE8C9406D763AE9A03E734480C0830E0300E099F89C07071E1964B843C173051FC55666F377413A7C58F1BFD8C04B6A00562497ED4DD5B0893CDCDED7766971FAF4B676737A35E0AC28654EBEC095146033C184FF9D480E200E3A8E63DA3B084FA9726FD2562C30695F9882C9F31F7B0A6805F4F65BD5EB9C00D09AF46C7367D3E4806071553FE980070372BDEFB2372137EDAAC6814A10090F308D52FE76091DDB4D7DC9581B7F45538585C1D3736F084916CBFB50C2A98C0BDCF5DC764153F4F99A6005543AEA87276F7D89ECA3255855EAC0B3C51827204872DF11E1094D479913398B0B561A300BB0D498F42C5A2A4673C4DB5CD4B5BD11F2FFC6417875FCEE974160743FF691347A7180C696051211D1B78B8144030119709B4CD25E077EE7477AE15B1B1B47739081C9B27E6C475E0BF29E0DD4FFDC0D95B897763F23BAC4F242405E03858B2377019EC685010C02DA99FE982921030E2BAC43D67E0E16C84C6DC35A243A7D68828DCBD71F561D6916F6DA7EC8B78D0DD4F6FF60706CE7F4F250606122C08B336E6297DB9209060CCB97FF8D5A2B082F2B8454C73B230CCC437AC36E1D306758829FEDB2516C39491CE3DB4BD593900AC1EFD3695066F8E2806A05553FEB8108665986EF8F0C0524A8BBF8A55927081B718E5EC73B011FCC406DC25B0A36625A9985C5DD757305561DF8D15DD1B48B0BC1EFC77C6B74EDF48B727F1365B4D4463010C2A9B3100404DC93DC814706090B5FBD64CD433617CD4761A66D1B2D475081A2E5F31F501D4F03C4DB46C5979C09C0FFC171587BD48DA2415A4033F1A034714E80A9B5050C038882EE9B5D42293771EB6ED64F1031D94760F45B1E2A614E85BBACF16D7D0D7D01F2DB28E6A08D28C7F5D1447967E7E88160054033F190364748B7C7930D2400DE9FE88D600C00135FAD54C75E3317CD2260C34A1C37245B989EC9C57E74051B00F2CA08C0A99517C2FFD6756F6CF2FF937E253173F6C7662652D2ECA8212229EDF6C2865D0714123A9F65CD550E1BCA564FA65F0B326D53989FD8C07E6C06495FF6CC4FCEE99608D0E8D3717271B9EC967E6C7D3FF6913462459DDBCA151300DADAFB9A46044A13288543D017150DDC437CCF51433E6050988280FA4F47285F1EFED041D2B18B19C1F5C0295553CAC2857D60617AC68A2B734083F6A9170E00DADAC8874412070D00AA42CF520E17DA567CC74A002D046D8383CFD76C6B5A093DF2C65CA188901BC7F5C16A7B7795CE8076646733D18D34664096A9A2050C00DC93DE9A4521071F378E63CC4F1207FE225CC3592A317150BA89D5F76759697C16E3FD5DD3B79C16C1DEDB777860E1E2806A441376DE872364489CF4EC6045408DB4C4BC762C2F3F14CE03873B0313CD0C6BDE5B4F70471DADCEDFC67E6A1D1B5CDAF76681E08A24C6E3C171786EA6BFAE70767024EC95322D448ACCC64F4F20929CEA9E4811050E369B528267425BDA7E2CFA1C4F2C7159998AC8C76C184C680AE4CA4DCC979617C1BFEE606573F9E28076773D33FD8046210481F595191311CD9BB8DA751105142B8A55C9484E1BD1472C86112C2D615C85898C9D4D4D49193DC39E69F491B137E7D3E65C4150CCDEA656483176AA912823048189C91412458AAAA9CD5A3E445C70A2068748425E86714D8671211C411DDEB68C9D4C4C491E43A5CB1284F5CB0D95B5F7513D26A5BF8729202364F0E52D3221B1DB9F101430C686F9875D0705081B8A52C33B425BDA7E7DDF4D1B3A690EC3B0DFD1776C084818E4904DD9A0DB589AF9C0607C77F0ADDD676B3373D6C5697753D28BC31342458785E8C80C31661D3D8826824E121294792BD5634F336600AAC9DFEF3F7C084F12AAE50DD298F472B5ED83056F66F2A3976B603317C1A1662169B9E5AB3C45168AD6A48E094D125C7A98068D4D405C8C512C86110B7F261882CEACF6667608561AF4FD47C5A0A917D9F3D17C1D70A78DB576715E33F696276444B3A9A5051211EE84EE8D6A302A3F308552C743147EFF6F79C74C0A7F54529882D8DB717F691E00B2CD07C5B08911DBE9C62B6D6BE5B29C2E206070E7827B2652D4DBDB451565D994E49C76101312008653D65E18438E077D811E1A2C614F9F8DC1D7223F4C6854B7BE0DD4EBDC0B9BBFC12B3833ADF5F272616537F58C75310F96C58A60290BDC93F9864C16250E3E884DF7490C3FA9717AD46D1B2D4D6AF1C9DF92433A4D1E00B78308FD99A55A90E9EE59415FAEADD433213625D9C7464F4E91C88A261200CDF6E8D2753E66350FA802A2086028E4556FD45B4F0D614D9D8DD5B268680A5A03B9DA44CDC5CA488C9AFD676962FCE3A760606117E28028777286DB8F0E0765CB99E68D5D4C1F1D3784498C580F13920C66CF4C0071704BCA9FCDD47A7A1B5404E4D746C6EB9E17DAFDDE603360FAE0C974607C78F490237158DCD087080F0A8695E48512050913388743D748050CCA4D60D25B012B2A5E9E8197C17E740C4815F8CC4BC4EB9A17D8A1DD637B6AF6E89363756078E98C30660F91C68B5B1311C784EA8F4C4C0A15298E08C1540D45C4477DD55B0138614FDF80C5C47A360A541EAC905CD6AC941F9BF9DD682662E5E4DC606E6A26E0CB256C4CC9C487090C4BCF99E48F4507481F30861D8C590910CE0C6DC953542F685C8898C3D57E360A541EAC9045CEBF9014D9FB9C66726EAEA39F7C7F7A3AE984686C5395928E0F1407C984A58B460F5D102F8344D1150311C4196DC9501B3E674982C2C1C171360A541EACCD4DC0B79A109BF7C16B3360FAE0C970697A33EB91352D4C9BC782020F01D199E584400C03523C844B99570F07C84E7ADF5D00316A58929882DB777F47581CFA8506C0A89802DAF4D3726E2DF6E29F28646632E491237B529DC59314090AC685A58B460F5D113E824A8C48050CDF4B6DC34D41336D4B94C2CFDD72230C4F00EE904BCEA8C256DEF3DC623360FAE0C9636D7238F18A2B66478A87850F0D5ECE97E88D4B0D0917718849CF004E19C85661D4100C3069069583D9D0737D0A571AF4D5069ABF9816D2F59C66726EAEBCCA23767C3AF0912F6C4F8187850F0D5EDF9FE78C5D03081B3A85528C580F1392556BC4560E31675883C2CFDD72231D5901F2CE47D3B1D71AD0F6DE767276E1E5DC7D60676DF695276E439EC6850B0517DD82E28440161F523C844B99520E0ACC5060C34A423074499881C5C87A6A47581CFA8506C0A18E17C7F6D6687867FCECDC706A7E6DF68023684C9D87850F0D5EDAC1BCDF5B4C0F1239841DD152100BC25720C551026461528389D6DD317B065648F9DB5FC0B68956D6F5DF2B7E6DAEFA82696E6278E68A2B385393CD8F010C15C79FE59C07010911648451CE5D0F0CCA4720C55102642A50988FDEDD6C770F4F5DF4D1459AA9961BD4F6DA6A6E77AEBCC0242B2378B5CB77385297CA93120516DC83EF814C11481F30861DC45A1213DF4B62CA5B413C6B50CA81D5D06D771E4816E5DC49D3EB9A17D8A1D370796AE1F896762B7039E8DE226A469BDD870C0D00CC9FEA8B460F0B09318245C34F0911C75120C5510264695C819DD9D76C6C47581CFA8543C8BD9C01D0B4D16A7038F8F4817B6A6324E09668604E9F92850F0E01DD9FFFC55A07140A368843D1150311C41974DF50083E2A5E9E81979C2A7500555DF4D1459AAB9C0CD3F6DB7D3360FAE0C967707133E88A21764DDCCA890D5B1CC783FF9D4B07481F30861DC0490919C1566DC9480A7167529CD7C1DD7C7000591CE3904BCEA8C21EC2F7C068336DF0F9C97E607D32E089237A0F91C68B604010DA9AB6B30C113B7C02CB56C3481343F22278CB46302C725A90ECDEC17E7D07535DF3D244A193B40FD4E8D7254B4EF4F8967A6A1315E09732475482C58F030111CDB5D9A46A0D08083A9352A26A151BDB5B51EB5F0631046AA5BFE9DC6A750C4912E3DB7BC4B68A11DAF4C1521D42D9C1A740404105D5B7094568BEECE62E1426C499F88D290C03087F9D4FC74C4051C84E62A61B2D105062A4BFE9E05B57247A3AD99B28E5A0951DC1FFE1606F75FCEE9713524705C39723666C97C489121965FB93FFAE400E032C308248D65E127E8C6041F2772B7A04749F98C9C073770A5016F3FD47CCB5980AD0DFCA667562FBEA9713637E39EBCB237B44F2EA83121423DA93EEAB4C101215398245C34F053DC64C7AC3461B5F73549F88D9DF6F360C431697F05CF2A08D3BDAF4C6606577C1E58076647756CDAA13516DAB89C90D0F459DF6C7874609130C1E8845CD4E0E0AFA4B6AF13E1D30714994CCDCC076761D3B3DF2CA7DD2A08B3DDBEFDF057C70E2E59D7C6E6B78E1892A034A97DB88050C569AD8EF8445620F0A32C64FCC51051DDD0C6ACA526F0C6149D183CED84855206816E5C841C2A0D94595DDD7715261FFE891672D3121EC8B2B644C86DADC42404388D4F0814412030E2C8448C34F0911C76E6BD05B03626D508189DEC17076084F16EA9F74FDEBA55DD6F5DD714160FCE08421273A5CD6803223429DC5A0090C00DBD6B6C846000C2B12A275C7491617CA4720E3460A3C5548949ED59A3D4B0C5716F4CA088BE5BF0ADAF79246544ECAC9936764553FE98066544997DB83402E04C593ABD50945430F78C90FA87D0F0C89676FC5564F306657B785C0D73F71071B10F8D26EC8A99C0BBFF5D06F5B6AF9E8DC506A632FADC7637003DBA3A8051811A8B0E2864D350F123B8451E33B241BC5477AC3780633617CF1AAC5DC7B4A0C481CE2CC4BC484F93FD0EEE46A7176F8E8BB7D637C24E884326A4E9CFEE6290E11CD84E58D5D2D161931BE54CE7A6029FB714F885B173A045E9C8882D7677D491410B7CE41CFA2D955DBBA83353D6FFAEE937F6D7C25F1C560250180C48209124587A5ABC7784244592CC926F755121BCE4B7DD25B1D1C685C829FEDB25C7D1B4F32F3DA6BC4B78D11D3F3D1646966D6E29C67606B22D18A15774E80CCE62C0F04CCBAE28A5B0314051EEB47CC480612DD500EC5530B62351B9C9FCB8F3A6B4F4B1CE5CA5B9CC5BE1DC1DCDD777864E7E2877D61443FEB8129742181CC923F1517C4F6AB8D51075B277A987B82580D1AC54B60C303347A7760D19CC5D622434C4E2EB7CB5BC4B79719D8FF8F5E3870C887F244777A22E0A32F6F44F2869253600D9BF6C4984C0C353F128A48C35C050CFE2240E76A420F496DD1C9D9926B7B193B5CF5D15CFEB69C0AC39AE0717144F0F9A47677603FEA8B465472B3EE83142C04DB82CE9A5B0D147C09A651C349055EE8416DC3520A2D65499488AC926A6A050628B2CD7581B08A1DC7A7E9206E5EB5FD9360762E0DA0961B037286DBB514122CE9F6FD855A0115155FB843D67E0E1AE64448CF520A5F46448589EAD7717B0C1516EFDB28C2A48A10D8FBDC647A66F8E89C67667C38EB802577489DC79514120CC6918B9F5A50394F6DC542CE57602EC6517AEB5B1C2C655A94ADACF6716B384E16E5C777F6C58A11C1FFD3616B6AE6E2803D667C3BBE843064559ADB83011409C994F8C64A0D0B472C8A40C74C051C874C61D44A00312A5E9E81ACFE7B6A255412F3FA44CDC5BF11DBFEF1697270F08D9F63773D32E989462D448ACCE6101311C784EE8B07060A105FBC68C74F2312C6516BE3501A32045E9C888C9D7C381A5E0797DF5EC2B09F4B87B4D6697103F8EE817B6C763AE1CB237B44F2C0D2603004DC9EDE86581709083AB856C358050DFE227CD55F0D3E7758DF88C0DE1F4F2B712CDEF966EE97BC78FBCEE7565851BBC9B347055D22C4892A6C4293DD83360917DC83EA8464070B132D92268768190DDD4763F451002B2161A295DFE5504F5F0F2FF2C658CDAA8B1DC7B4D77D7803D2E886476D6133E481056C4F86CC9E14600399F6C6874D170A196CD960CB49130AA9716BD27D1A2D76589F98E8DB6D7D0A4F1CE5C769A192AA1BC7F3C2713350F9E897632536238FB62377019DCB8C372D2CFB93F99E4001035C62CB61C74F2F1CC3476DD2164D286D539C8BC1C66C224B1B55B79C53C8A8891DC7E9DD6B7C77FCE29C5F606533E9D82F6E5197DB950F0E04DC93F6C9753E48207A8849CD4F3C1DC04F78941C4655575885CCC3D075481B5410F2CD5B81F8D93FD0EEFD677766F6F9DA31727A38E8822B7752C8DB890F1439CB9FE69E1B58311531D814FD6B1211CA477DD51C4655614F83BEC9C66A6A071B4EB7D14ACB958B17D6FFC1763340E7E89367603B74A096642F019CDC8A0C4C45C683E7C4090C131076E171F1781217D95620F5520A3A741DC3DC9C82154B0C4F53F1CD4781F8D93BC7FFD371784CF7E79770713B74D686346A5186C088074E23C19AEEBB5011121932A444C85E030A8B0B04C04D007140589D89D8D75971055E5BB59B5B83ECF90ED8F4D3713366EDE8F25A6B6733F78B2377629EC695052804C692E78D2942491F7F9B4FCC5C4E1BD1472E8B504F69240CC3DB82823128470A53B19E08D5BC891D95B897764150ECFE8676682064D986276F42DCCC9E05424596D6A9CD5A406630308A42F05E1311DC506DC33E272B704DA099C9C06651075D1CD6BE08C5A48D1988C197764003DCE38676777D33F1B43366538BE69614090AC6B78B9C1447155C2B824BC7063B5B99106A9C1B5F6D6007D4DC9ED6323D590917B89B1893A1D65DD1C7B2554F5CD2E8865D647E33C38A344A4597C79209141CA8D6F98D4F0714192DD67D87483D7EED4768F157013B6B4AA19EC3D15E184C0B41E2900D91F78C5690AA80703026A5BF873C202364F0CA63331587A9C3331916DC93E6BA460D1259038E5ED2570F0CCC5020C3460A5F4A49A099C9C06651075D1CE5D349D5AC9616E5E8DD667870E68D9C60756162AB812A6F2181C88B100C00A89FB8E80C321413389947CF7D0912CC512BFA77012B614F9F89D8925A6019571CE5DB5AFDAC9C00C5F6DD77782DF0F5971320402FF691236E739DC692453C36D185DCA77E545220328444D1420E1D874776C33E19327C539498ACE24D47264B16F9EA6BF196961BDEFFC6056E6BF0E19E20373D32E9894623499DDA925D3B65EF93FFAE400E033D2B9F54CB59150ACC5159A6634F2A775883D1F7B27B761A5A03FE904CCDA9F928D0FFD9487870E6EC9576521315E09732405397C892052300DA82E28E400107083AA84EC3520E3BC74567C85B6F0F76529289DFC12C2A2F5201E4CA28F3A09D58FDFBC6254B6AE7F9BB5C057A6485B632624299FE870C0B539CF6C88D5B1627183BA874EE780F10DD4776D26A000C70528389ACF57A761C521DF2F746D5A09578E2C9F356786DF18DD7514A4709D0B603516FB3E4A345604BC498E0E84D0001143A87568C5F0C12A94378D6100A2761069A8DDAC66D79101516EFDB28EFA08D39C5F3F0707B65F0FFB461607656D680327651B6C0A1051426C497F89B6D07100F1EEB65C7491438DB476BE55B1D2B6D5B988FCDC67A5B015A1AF9BE58CEB29C0AC6F2D769712DF0F59713565C10D1B2075164AEE48F03120ADB99ED9C75350F123B8451D11B2E2AF5617BD44C0A31706B949EDFDB7076356B01F8D841CDA0B511C6EEB2737067F0EF8774054F25E3D768674D9EA9A5120504DC93DB9A4601030F2CBC26ED4B0510FD4A7CC35F0B5F47588398EBD76B5B3B7730F8D05CC4BD8D28C7F5C2606F77EC8DD760253172A096663E01AE8BC3133C4793D6ADC80D47155E5FDA08CC4D100CC0546FD25B00396254928982DB717E063B3EF8C441CDA9985780B482253554FCE3967C726076CBB1663211DC99DD40370CC6C0BFD3091A504864CB54D401564687122786790A3C6F52DEDE9C832F28580B42B7F841D3A09F17CDB5843D333395FBA17C667833F196464A4F86CC940E0511FA93EA8C6F0B0A195FB852D068140CFE2266943E2C3A7649B79EC9D75C7D1B4F1AF1D74BC0B19C3BDDFBDB6B586DF2E49C76055024E08432667397C489140531C084EE894D622F122B8E54CC5E1439CC5642C74D1B0D614E8183C2C17A51075D1CD6BE69C5A89016DCE9C6777C77FAFFF2335E7638E1B84C034593DD873F090BC293E89C293507152BAD49D0680910CE4E6BE95C053A6749F187CEB27A7F1C525DF2C64D9AA0920ADBB4D77D7803A6BDC51372713CAB82290372BDEFB2372137EDAAC6814A10090F308D52FE6C0910CD4D79D51E2B3A62589F88C9C0435D11581FE2CD41CEAB8A24E5FBC66D6E03C5E2816754663FF1A823705293CE83603A12F983EE9A502B081A30994BC34F0911C77666D45B0E3B045394988CC177791B5E73B2FC67F59ABA37F8CAE7515851DBCCBF56201301F78C32667180C685051316E593E6875B1B66122B8F4ACE150412C5226CC25F083A6A49DF89D4D7246E1A4816E5C806C4BD9C43C3E9C1606F75E5FD9E3D606B3385AD327751A1CC88043200D983EE9B5D23662B118E52E7551513FB477DC94B1D3C616AF1AFDED77E6C0C6C1AF9DA47D6808139B5D3DC717871FBE88644777A22E0A32F6F44F2FEA3252B29F1D6A4AC0936333973BC63E6173436FC0221F56A4F6E3607C1DC96822F182A4916F6CA4DF5AA9614DDFFDE752E31C6E39363767B39F1E52F6E4095CCC90A1000CFF6D88046153115318F49D53B3331EF7659E76C2A03535286DA98812D56065F16CBF341C2B7960BDAFCC6255C6DE1E4BF72696437F7801A50518BE783146020D086EA864D27080A369949CC560510DD717AD4570138776AF1"

def decode_str(eax_value):
    decoded_char = "xx"

    while(decoded_char != "\x00"):
        dl = eax_value & 0x3F
        dl = xor_position[dl*2:dl*2+2]
        decoded_char = chr(int(heap_allocate[eax_value*2:eax_value*2+2], 16) ^ int(dl, 16))
        lst_str.append(decoded_char)
        eax_value = eax_value + 1

    return ''.join(lst_str).replace('\x00', '')

for x in range(0x410010,0x410650, 0xC):

    bytes_read_api = hex(bv.read_int(x+4, 4))
    bytes_read_dll = hex(bv.read_int(x+8, 4))
    
    if len(bytes_read_api) > 0 and len(bytes_read_api) <= 6:
        api_converted_value = int(bytes_read_api.replace('0x', ''),16)
        dll_converted_value = int(bytes_read_dll.replace('0x', ''),16)

        if api_converted_value > 0 and dll_converted_value > 0:
            dll_name = decode_str(dll_converted_value)
            api_name = decode_str(api_converted_value)

            dll_api_name = f"v_{dll_name}_{api_name}".replace('.', '_')
            print(f"[+] {hex(x)} - {dll_api_name}")

            # Rename with the dll_api name
            bv.define_user_data_var(x, "void*", str(dll_api_name))
