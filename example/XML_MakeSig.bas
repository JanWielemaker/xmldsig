Attribute VB_Name = "XML_MakeSig"
Option Explicit

' $Id: XML_MakeSig.bas $
' $Date: 2009-01-16 $

' This module uses functions from the CryptoSys (tm) PKI Toolkit available from
' <www.cryptosys.net/pki/>.
' Include the module `basCrPKI' in your project.

' Ref: XML-Signature Syntax and Processing <http://www.w3.org/TR/xmldsig-core/>
'      RFC 3275 <http://www.ietf.org/rfc/rfc3275.txt>
'      XML Signature WG <http://www.w3.org/Signature/>
'      Canonical XML Version 1.0 <http://www.w3.org/TR/2001/REC-xml-c14n-20010315/>
'      RFC 3076 <http://www.ietf.org/rfc/rfc3076.txt>

' Test with the XML Security Library `Online XML Digital Signature Verifer'
' at <http://www.aleksey.com/xmlsec/xmldsig-verifier.html>

'***************************** COPYRIGHT NOTICE ****************************
' This code was originally written by David Ireland and is copyright
' (C) 2006-9 DI Management Services Pty Ltd <www.di-mgt.com.au>.
' Provided "as is". No warranties. Use at your own risk. You must make
' your own assessment of its accuracy and suitability for your own purposes.
' It is not to be altered or distributed, except as part of an application.
' You are free to use it in any application, provided this copyright notice
' is left unchanged.
'************************** END OF COPYRIGHT NOTICE ************************


Public Sub Test_XMLMakeSig()
' User to change:
    Const TEST_PATH As String = "C:\Test\"
' Input parameters:
    Dim strTextTBS As String    ' = raw text to be signed
    Dim strPriKeyFile As String ' Encrypted pkcs-8 private key file
    Dim strPassword As String
    Dim strCertFile As String   ' Signer's X.509 certificate file that matches the private key
' Output parameters:
    Dim strXMLFileName As String
    
    strTextTBS = "some text" & vbCrLf & "  with spaces and CR-LF."
    strPriKeyFile = TEST_PATH & "AlicePrivRSASign_epk.pem"
    strPassword = "password"
    strXMLFileName = TEST_PATH & "XmlAliceSig.xml"
    
    If XMLMakeSigWithKeyData(strXMLFileName, strTextTBS, strPriKeyFile, strPassword) Then
        Debug.Print "XMLMakeSig succeeded."
    End If
    
End Sub
    
Public Function XMLMakeSigWithKeyData(strXMLFileName As String, strTextTBS As String, _
    strPriKeyFile As String, strPassword As String) As Boolean
' Creates XML signature file given raw text-to-be-signed, encrypted pkcs-8 private key file and password.
    Dim strCanonData As String
    Dim abMessage() As Byte
    Dim abDigest() As Byte
    Dim nDataLen As Long
    Dim nRet As Long
    Dim strDigestBase64 As String
    Dim strSignature64 As String
    Dim abBlock() As Byte
    Dim strPrivateKey As String
    Dim nmLen As Long
    Dim nkLen As Long
    Dim abCertData() As Byte
    Dim strXmlData As String
    Dim strX509Data As String
    Dim strSignedInfoDisplay As String
    Dim strSignedInfoCanonic As String
    Dim strXmlKey As String
    Dim nXmlKeyLen As Long
    
    ' Canonicalize the data into the form to be digested
    ' Convert any CR-LF pairs to single LF
    ' TODO: convert non-US-ASCII to UTF-8
    strCanonData = Replace(strTextTBS, vbCrLf, vbLf)
    strCanonData = "<Object xmlns=""http://www.w3.org/2000/09/xmldsig#"" Id=""object"">" & strCanonData & "</Object>"
    Debug.Print "CANON DATA='" & strCanonData & "'"
    ' Convert data string to unambiguous array of bytes
    abMessage = StrConv(strCanonData, vbFromUnicode)
    ' Display data in hex format
    Debug.Print "HEX(DATA)=" & cnvHexStrFromBytes(abMessage)
    nDataLen = UBound(abMessage) - LBound(abMessage) + 1
    
    ' Create SHA-1 message digest of data in byte format
    ReDim abDigest(PKI_SHA1_BYTES - 1) ' Don't forget to do this!
    nRet = HASH_Bytes(abDigest(0), PKI_SHA1_BYTES, abMessage(0), nDataLen, PKI_HASH_SHA1)
    Debug.Print "SHA-1(DATA)=" & cnvHexStrFromBytes(abDigest)
    
    ' Convert SHA-1 digest to base64 format
    strDigestBase64 = cnvB64StrFromBytes(abDigest)
    Debug.Print strDigestBase64
    
    ' Now we create the display and canonical forms of the SignedInfo element
    ' We cheat and do this by hard-coding.
    strSignedInfoDisplay = "<SignedInfo>" & vbCrLf & _
        "  <CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315"" />" & vbCrLf & _
        "  <SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1"" />" & vbCrLf & _
        "  <Reference URI=""#object"">" & vbCrLf & _
        "    <DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1"" />" & vbCrLf & _
        "    <DigestValue>" & strDigestBase64 & "</DigestValue>" & vbCrLf & _
        "  </Reference>" & vbCrLf & _
        "</SignedInfo>"
        
    ' To canonicalize the SignedInfo, do the following:-
    ' 1. Replace any CR-LF pairs with single LF char
    ' 2. Add the xmlns attribute to the SignedInfo tag
    ' 3. Convert the three empty 'Method' elements to start-end tag pairs
    ' 4. Do NOT change any other whitespace chars outside the tags
    ' -- assumes all other c14n aspects are dealt with in the hard-coding
    strSignedInfoCanonic = "<SignedInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">" & vbLf & _
        "  <CanonicalizationMethod Algorithm=""http://www.w3.org/TR/2001/REC-xml-c14n-20010315""></CanonicalizationMethod>" & vbLf & _
        "  <SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""></SignatureMethod>" & vbLf & _
        "  <Reference URI=""#object"">" & vbLf & _
        "    <DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""></DigestMethod>" & vbLf & _
        "    <DigestValue>" & strDigestBase64 & "</DigestValue>" & vbLf & _
        "  </Reference>" & vbLf & _
        "</SignedInfo>"
        
    ' And sign the canonical form using rsa-sha1
    ' Convert ANSI text to bytes
    abMessage = StrConv(strSignedInfoCanonic, vbFromUnicode)
    
    Debug.Print "M (ansi): '" & StrConv(abMessage, vbUnicode) & "'"
    Debug.Print "M (hex):  " & cnvHexStrFromBytes(abMessage)
    ' Compute SHA-1 digest as a check...
    nRet = HASH_Bytes(abDigest(0), PKI_SHA1_BYTES, abMessage(0), nDataLen, PKI_HASH_SHA1)
    Debug.Print "SHA-1(M)=" & cnvHexStrFromBytes(abDigest)
    
    ' Read in the private key from encrypted file
    strPrivateKey = rsaReadPrivateKey(strPriKeyFile, "password")
    If Len(strPrivateKey) = 0 Then
        MsgBox "Cannot read RSA key file '" & strPriKeyFile & "'", vbCritical
        Exit Function
    End If
    
    ' To sign: first encode the message, then "encrypt" with RSA
    ' Compute lengths
    nmLen = UBound(abMessage) - LBound(abMessage) + 1
    nkLen = RSA_KeyBytes(strPrivateKey)
    Debug.Print "Key is " & nkLen & " bytes long"
    Debug.Print "Message is " & nmLen & " bytes long"
    
    ' Encode for signature
    ReDim abBlock(nkLen - 1)
    nRet = RSA_EncodeMsg(abBlock(0), nkLen, abMessage(0), nmLen, PKI_EMSIG_PKCSV1_5)
    Debug.Print "RSA_EncodeMsg returns " & nRet & " (expected 0)"
    Debug.Print "EM: " & cnvHexStrFromBytes(abBlock)
    
    ' Sign using RSA private key
    nRet = RSA_RawPrivate(abBlock(0), nkLen, strPrivateKey, 0)
    Debug.Print "SG: " & cnvHexStrFromBytes(abBlock)

    ' Create an XML version of the public key
    ' (the RSA public key is kept in the private key info)
    ' DANGER: do NOT export the private part as well!
    nXmlKeyLen = RSA_ToXMLString("", 0, strPrivateKey, PKI_XML_EXCLPRIVATE)
    If (nXmlKeyLen < 0) Then
        MsgBox "Unable to create XML version of public key.", vbCritical
        Exit Function
    End If
    strXmlKey = String(nXmlKeyLen, " ")
    nRet = RSA_ToXMLString(strXmlKey, Len(strXmlKey), strPrivateKey, PKI_XML_EXCLPRIVATE)
    
    ' Clear the internal private key for security
    Call WIPE_String(strPrivateKey, Len(strPrivateKey))
    
    ' Convert the signature value to base64
    strSignature64 = cnvB64StrFromBytes(abBlock)
    Debug.Print "SG: " & strSignature64

    ' Now we have all we need to compose the standard XML document
    ' and insert our own base64 elements
    ' NOTE: this assumes the text-to-be-signed is UTF-8
    strXmlData = "<?xml version=""1.0"" encoding=""UTF-8""?>" & vbCrLf & _
        "<Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">" & vbCrLf & _
        "" & strSignedInfoDisplay & vbCrLf & _
        "<SignatureValue>" & strSignature64 & "</SignatureValue>" & vbCrLf & _
        "<KeyInfo>" & vbCrLf & _
        "  <KeyValue>" & vbCrLf & _
        "    " & strXmlKey & vbCrLf & _
        "  </KeyValue>" & vbCrLf & _
        "</KeyInfo>" & vbCrLf & _
        "<Object Id=""object"">" & strTextTBS & "</Object>" & vbCrLf & _
        "</Signature>" & vbCrLf

    ' Save XML as a text file - clobbering any existing file without question
    If WriteFileFromString(strXMLFileName, strXmlData) Then
        ' SUCCESS!
        Debug.Print "Created file '" & strXMLFileName & "'"
        XMLMakeSigWithKeyData = True
    Else
        MsgBox "Failed to create XML file", vbCritical
    End If
    
End Function

Private Function WriteFileFromString(sFilePath As String, strIn As String) As Boolean
' Creates a file from a string. Clobbers any existing file.
On Error GoTo OnError
    Dim hFile As Integer
    
    If Len(Dir(sFilePath)) > 0 Then
        Kill sFilePath
    End If
    hFile = FreeFile
    Open sFilePath For Binary Access Write As #hFile
    Put #hFile, , strIn
    Close #hFile
    WriteFileFromString = True
Done:
    Exit Function
OnError:
    Resume Done
    
End Function


