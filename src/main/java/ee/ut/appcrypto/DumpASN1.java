package ee.ut.appcrypto;

import java.io.FileInputStream;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;

public class DumpASN1 {

  public static void main(String[] args) throws Exception {
    FileInputStream in = new FileInputStream(args[0] + "priv.pem");
    ASN1Primitive der = new ASN1InputStream(in).readObject();
    System.out.println("PEM: " + ASN1Dump.dumpAsString(der));
//    PEM: Unknown d 2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949457041494241414b43415145

    in = new FileInputStream(args[0] + "priv.Der");
    der = new ASN1InputStream(in).readObject();
    System.out.println("DER: " + ASN1Dump.dumpAsString(der));
//    PER: DER Sequence
//    Integer(0)
//    Integer(24967864669034856740294328353564664978535409550378246223599208786901771720859763742103892903306673800081769253816230567791012155347232532901517172076701922840732780455221981700904114520428875237934392791429917800346853295474274622817778942432958526828504146822885966560405567888742491747030060517291243907726964849157712973565054366561285069732329712437274018240241411953573086051399823362085960100590143272253323230274417418231212536697778050272513069835851359874812197239189280899882629544968759032705353767673465412079957848776921015079931562295031549327890340858461488688493804230155670775753663900012729477532637)
//    Integer(65537)
//    Integer(4955323187667064125928991697740445814971849062693895793679217979023015163544607580352248882208674582566543672801435997913509850994117117894472341687926849114079241884448057066750992837133502910108986481500968015458619113084729084623813276534255329942755289954152276836766944192271138290639180877190094290367281110888505885127778445503011688714690833363188877216453349432405399386493979246418258809628785582892180009166596009979631068427636461418420245855187727309214458461031926560172244409391223459276113381712121217767508943153319389566526653313758668112625071943319856019586531407968054726561274194444944684622689)
//    Integer(173996080891588368519449403544054008411268643670175997642247056443830271302416002059805284835349884163267413265465238664907105743963743119062588978883647919735954495986666106589952094052031510818898879893917026674381153378579880448954899435068882137609012359384950138849267569203565463531777234744441954628553)
//    Integer(143496707173488401023578422377208289868075059590661175888688864873342841475440890239622363487420377710660010077976343014058077102656409715224321664883596889035805735387640473771774717137023374075380643352140970257638384685717713855897299576822678561303905576853627505157528981702285783149369798862633659898229)
//    Integer(53637530284461598931877203713940569936568051758068963797035526211677418422001472292205108099677643312182302366635552691565348693795863439498626503202562505491943309617752038565036577141663375086961778392309774477051473849999989696053158266119850249875869763593911037355566362522233746734401871821138605815961)
//    Integer(106795426894531284006363390931051685892173291904336464195352234374434244670409530821331168333901901564573324863104751979960674286007390998368345960368912801359864271228957140366789932837302822383183406007303901983861211423255283173190576115164352149588751308589585754063482858271342738805720614912567813014573)
//    Integer(142078218776722188151740261103768493560731681994872751900561668432222666107176505815259949528804283811596756390947789603076589199402005742981270086774423648525940747991576029620911993205919414684155800781981880030986064454113006645898155899543509628491670997029336857351241948961966375282537501014180087630983)

    
    in = new FileInputStream(args[0] + "priv.pk8");
    der = new ASN1InputStream(in).readObject();
    System.out.println("PK8: " + ASN1Dump.dumpAsString(der));
//    PK8: DER Sequence
//        Integer(0)
//        DER Sequence
//            ObjectIdentifier(1.2.840.113549.1.1.1)
                // --> http://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
                //   = RSA encryption
//            NULL
//        DER Octet String[1192] 
    
    
    in = new FileInputStream(args[0] + "priv.crypt.pk8");
    der = new ASN1InputStream(in).readObject();
    System.out.println("PK8 (password): " + ASN1Dump.dumpAsString(der));
//    PK8: DER Sequence
//        DER Sequence
//            ObjectIdentifier(1.2.840.113549.1.5.3)
                // --> http://www.alvestrand.no/objectid/1.2.840.113549.1.5.3.html
                //   = pbeWithMD5AndDES-CBC
//            DER Sequence
//                DER Octet String[8] 
//                Integer(2048)
//        DER Octet String[1224] 
  }
}
