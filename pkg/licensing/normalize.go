package licensing

import (
	"regexp"
	"strings"

	expr "github.com/aquasecurity/trivy/pkg/licensing/expression"
)

func licence(name string, hasPlus bool) expr.SimpleExpr {
	return expr.SimpleExpr{License: name, HasPlus: hasPlus}
}

var mapping = map[string]expr.SimpleExpr{
	// Simple mappings (i.e. that could be parsed by SpdxExpression.parse, at least without space)
	// modified from https://github.com/oss-review-toolkit/ort/blob/fc5389c2cfd9c8b009794c8a11f5c91321b7a730/utils/spdx/src/main/resources/simple-license-mapping.yml

	// Ambiguous simple mappings (mapping reason not obvious without additional information)
	"AFL":          licence(expr.AFL30, false),
	"AGPL":         licence(expr.AGPL30, false),
	"AL-2":         licence(expr.Apache20, false),
	"AL-2.0":       licence(expr.Apache20, false),
	"APACHE":       licence(expr.Apache20, false),
	"APACHE-STYLE": licence(expr.Apache20, false),
	"ARTISTIC":     licence(expr.Artistic20, false),
	"ASL":          licence(expr.Apache20, false),
	"BSD":          licence(expr.BSD3Clause, false),
	"BSD*":         licence(expr.BSD3Clause, false),
	"BSD-LIKE":     licence(expr.BSD3Clause, false),
	"BSD-STYLE":    licence(expr.BSD3Clause, false),
	"BSD-VARIANT":  licence(expr.BSD3Clause, false),
	"CDDL":         licence(expr.CDDL10, false),
	"ECLIPSE":      licence(expr.EPL10, false),
	"EPL":          licence(expr.EPL10, false),
	"EUPL":         licence(expr.EUPL10, false),
	"FDL":          licence(expr.GFDL13, true),
	"GFDL":         licence(expr.GFDL13, true),
	"GPL":          licence(expr.GPL20, true),
	"LGPL":         licence(expr.LGPL20, true),
	"MPL":          licence(expr.MPL20, false),
	"NETSCAPE":     licence(expr.NPL11, false),
	"PYTHON":       licence(expr.Python20, false),
	"ZOPE":         licence(expr.ZPL21, false),

	// Non-ambiguous simple mappings
	"0BSD":                             licence(expr.ZeroBSD, false),
	"AFL-1.1":                          licence(expr.AFL11, false),
	"AFL-1.2":                          licence(expr.AFL12, false),
	"AFL-2":                            licence(expr.AFL20, false),
	"AFL-2.0":                          licence(expr.AFL20, false),
	"AFL-2.1":                          licence(expr.AFL21, false),
	"AFL-3.0":                          licence(expr.AFL30, false),
	"AGPL-1.0":                         licence(expr.AGPL10, false),
	"AGPL-3.0":                         licence(expr.AGPL30, false),
	"APACHE-1":                         licence(expr.Apache10, false),
	"APACHE-1.0":                       licence(expr.Apache10, false),
	"APACHE-1.1":                       licence(expr.Apache11, false),
	"APACHE-2":                         licence(expr.Apache20, false),
	"APACHE-2.0":                       licence(expr.Apache20, false),
	"APL-2":                            licence(expr.Apache20, false),
	"APL-2.0":                          licence(expr.Apache20, false),
	"APSL-1.0":                         licence(expr.APSL10, false),
	"APSL-1.1":                         licence(expr.APSL11, false),
	"APSL-1.2":                         licence(expr.APSL12, false),
	"APSL-2.0":                         licence(expr.APSL20, false),
	"ARTISTIC-1.0":                     licence(expr.Artistic10, false),
	"ARTISTIC-1.0-CL-8":                licence(expr.Artistic10cl8, false),
	"ARTISTIC-1.0-PERL":                licence(expr.Artistic10Perl, false),
	"ARTISTIC-2.0":                     licence(expr.Artistic20, false),
	"ASF-1":                            licence(expr.Apache10, false),
	"ASF-1.0":                          licence(expr.Apache10, false),
	"ASF-1.1":                          licence(expr.Apache11, false),
	"ASF-2":                            licence(expr.Apache20, false),
	"ASF-2.0":                          licence(expr.Apache20, false),
	"ASL-1":                            licence(expr.Apache10, false),
	"ASL-1.0":                          licence(expr.Apache10, false),
	"ASL-1.1":                          licence(expr.Apache11, false),
	"ASL-2":                            licence(expr.Apache20, false),
	"ASL-2.0":                          licence(expr.Apache20, false),
	"BCL":                              licence(expr.BCL, false),
	"BEERWARE":                         licence(expr.Beerware, false),
	"BOOST":                            licence(expr.BSL10, false),
	"BOOST-1.0":                        licence(expr.BSL10, false),
	"BOUNCY":                           licence(expr.MIT, false),
	"BSD-2":                            licence(expr.BSD2Clause, false),
	"BSD-2-CLAUSE":                     licence(expr.BSD2Clause, false),
	"BSD-2-CLAUSE-FREEBSD":             licence(expr.BSD2ClauseFreeBSD, false),
	"BSD-2-CLAUSE-NETBSD":              licence(expr.BSD2ClauseNetBSD, false),
	"BSD-3":                            licence(expr.BSD3Clause, false),
	"BSD-3-CLAUSE":                     licence(expr.BSD3Clause, false),
	"BSD-3-CLAUSE-ATTRIBUTION":         licence(expr.BSD3ClauseAttribution, false),
	"BSD-3-CLAUSE-CLEAR":               licence(expr.BSD3ClauseClear, false),
	"BSD-3-CLAUSE-LBNL":                licence(expr.BSD3ClauseLBNL, false),
	"BSD-4":                            licence(expr.BSD4Clause, false),
	"BSD-4-CLAUSE":                     licence(expr.BSD4Clause, false),
	"BSD-4-CLAUSE-UC":                  licence(expr.BSD4ClauseUC, false),
	"BSD-PROTECTION":                   licence(expr.BSDProtection, false),
	"BSL":                              licence(expr.BSL10, false),
	"BSL-1.0":                          licence(expr.BSL10, false),
	"CC-BY-1.0":                        licence(expr.CCBY10, false),
	"CC-BY-2.0":                        licence(expr.CCBY20, false),
	"CC-BY-2.5":                        licence(expr.CCBY25, false),
	"CC-BY-3.0":                        licence(expr.CCBY30, false),
	"CC-BY-4.0":                        licence(expr.CCBY40, false),
	"CC-BY-NC-1.0":                     licence(expr.CCBYNC10, false),
	"CC-BY-NC-2.0":                     licence(expr.CCBYNC20, false),
	"CC-BY-NC-2.5":                     licence(expr.CCBYNC25, false),
	"CC-BY-NC-3.0":                     licence(expr.CCBYNC30, false),
	"CC-BY-NC-4.0":                     licence(expr.CCBYNC40, false),
	"CC-BY-NC-ND-1.0":                  licence(expr.CCBYNCND10, false),
	"CC-BY-NC-ND-2.0":                  licence(expr.CCBYNCND20, false),
	"CC-BY-NC-ND-2.5":                  licence(expr.CCBYNCND25, false),
	"CC-BY-NC-ND-3.0":                  licence(expr.CCBYNCND30, false),
	"CC-BY-NC-ND-4.0":                  licence(expr.CCBYNCND40, false),
	"CC-BY-NC-SA-1.0":                  licence(expr.CCBYNCSA10, false),
	"CC-BY-NC-SA-2.0":                  licence(expr.CCBYNCSA20, false),
	"CC-BY-NC-SA-2.5":                  licence(expr.CCBYNCSA25, false),
	"CC-BY-NC-SA-3.0":                  licence(expr.CCBYNCSA30, false),
	"CC-BY-NC-SA-4.0":                  licence(expr.CCBYNCSA40, false),
	"CC-BY-ND-1.0":                     licence(expr.CCBYND10, false),
	"CC-BY-ND-2.0":                     licence(expr.CCBYND20, false),
	"CC-BY-ND-2.5":                     licence(expr.CCBYND25, false),
	"CC-BY-ND-3.0":                     licence(expr.CCBYND30, false),
	"CC-BY-ND-4.0":                     licence(expr.CCBYND40, false),
	"CC-BY-SA-1.0":                     licence(expr.CCBYSA10, false),
	"CC-BY-SA-2.0":                     licence(expr.CCBYSA20, false),
	"CC-BY-SA-2.5":                     licence(expr.CCBYSA25, false),
	"CC-BY-SA-3.0":                     licence(expr.CCBYSA30, false),
	"CC-BY-SA-4.0":                     licence(expr.CCBYSA40, false),
	"CC0":                              licence(expr.CC010, false),
	"CC0-1.0":                          licence(expr.CC010, false),
	"CDDL-1":                           licence(expr.CDDL10, false),
	"CDDL-1.0":                         licence(expr.CDDL10, false),
	"CDDL-1.1":                         licence(expr.CDDL11, false),
	"COMMONS-CLAUSE":                   licence(expr.CommonsClause, false),
	"CPAL":                             licence(expr.CPAL10, false),
	"CPAL-1.0":                         licence(expr.CPAL10, false),
	"CPL":                              licence(expr.CPL10, false),
	"CPL-1.0":                          licence(expr.CPL10, false),
	"ECLIPSE-1.0":                      licence(expr.EPL10, false),
	"ECLIPSE-2.0":                      licence(expr.EPL20, false),
	"EDL-1.0":                          licence(expr.BSD3Clause, false),
	"EGENIX":                           licence(expr.EGenix, false),
	"EPL-1.0":                          licence(expr.EPL10, false),
	"EPL-2.0":                          licence(expr.EPL20, false),
	"EUPL-1.0":                         licence(expr.EUPL10, false),
	"EUPL-1.1":                         licence(expr.EUPL11, false),
	"EXPAT":                            licence(expr.MIT, false),
	"FACEBOOK-2-CLAUSE":                licence(expr.Facebook2Clause, false),
	"FACEBOOK-3-CLAUSE":                licence(expr.Facebook3Clause, false),
	"FACEBOOK-EXAMPLES":                licence(expr.FacebookExamples, false),
	"FREEIMAGE":                        licence(expr.FreeImage, false),
	"FTL":                              licence(expr.FTL, false),
	"GFDL-1.1":                         licence(expr.GFDL11, false),
	"GFDL-1.1-INVARIANTS":              licence(expr.GFDL11WithInvariants, false),
	"GFDL-1.1-NO-INVARIANTS":           licence(expr.GFDL11NoInvariants, false),
	"GFDL-1.2":                         licence(expr.GFDL12, false),
	"GFDL-1.2-INVARIANTS":              licence(expr.GFDL12WithInvariants, false),
	"GFDL-1.2-NO-INVARIANTS":           licence(expr.GFDL12NoInvariants, false),
	"GFDL-1.3":                         licence(expr.GFDL13, false),
	"GFDL-1.3-INVARIANTS":              licence(expr.GFDL13WithInvariants, false),
	"GFDL-1.3-NO-INVARIANTS":           licence(expr.GFDL13NoInvariants, false),
	"GFDL-NIV-1.3":                     licence(expr.GFDL13NoInvariants, false),
	"GO":                               licence(expr.BSD3Clause, false),
	"GPL-1":                            licence(expr.GPL10, false),
	"GPL-1.0":                          licence(expr.GPL10, false),
	"GPL-2":                            licence(expr.GPL20, false),
	"GPL-2+-WITH-BISON-EXCEPTION":      licence(expr.GPL20withbisonexception, true),
	"GPL-2.0":                          licence(expr.GPL20, false),
	"GPL-2.0-WITH-AUTOCONF-EXCEPTION":  licence(expr.GPL20withautoconfexception, false),
	"GPL-2.0-WITH-BISON-EXCEPTION":     licence(expr.GPL20withbisonexception, false),
	"GPL-2.0-WITH-CLASSPATH-EXCEPTION": licence(expr.GPL20withclasspathexception, false),
	"GPL-2.0-WITH-FONT-EXCEPTION":      licence(expr.GPL20withfontexception, false),
	"GPL-2.0-WITH-GCC-EXCEPTION":       licence(expr.GPL20withGCCexception, false),
	"GPL-3":                            licence(expr.GPL30, false),
	"GPL-3+-WITH-BISON-EXCEPTION":      licence(expr.GPL20withbisonexception, true),
	"GPL-3.0":                          licence(expr.GPL30, false),
	"GPL-3.0-WITH-AUTOCONF-EXCEPTION":  licence(expr.GPL30withautoconfexception, false),
	"GPL-3.0-WITH-GCC-EXCEPTION":       licence(expr.GPL30withGCCexception, false),
	"GPLV2+CE":                         licence(expr.GPL20withclasspathexception, true),
	"GUST-FONT":                        licence(expr.GUSTFont, false),
	"HSQLDB":                           licence(expr.BSD3Clause, false),
	"IMAGEMAGICK":                      licence(expr.ImageMagick, false),
	"IPL-1.0":                          licence(expr.IPL10, false),
	"ISC":                              licence(expr.ISC, false),
	"ISCL":                             licence(expr.ISC, false),
	"JQUERY":                           licence(expr.MIT, false),
	"LGPL-2":                           licence(expr.LGPL20, false),
	"LGPL-2.0":                         licence(expr.LGPL20, false),
	"LGPL-2.1":                         licence(expr.LGPL21, false),
	"LGPL-3":                           licence(expr.LGPL30, false),
	"LGPL-3.0":                         licence(expr.LGPL30, false),
	"LGPLLR":                           licence(expr.LGPLLR, false),
	"LIBPNG":                           licence(expr.Libpng, false),
	"LIL-1.0":                          licence(expr.Lil10, false),
	"LINUX-OPENIB":                     licence(expr.LinuxOpenIB, false),
	"LPL-1.0":                          licence(expr.LPL10, false),
	"LPL-1.02":                         licence(expr.LPL102, false),
	"LPPL-1.3C":                        licence(expr.LPPL13c, false),
	"MIT":                              licence(expr.MIT, false),
	// MIT No Attribution (MIT-0) is not yet supported by google/licenseclassifier
	"MIT-0":                licence(expr.MIT, false),
	"MIT-LIKE":             licence(expr.MIT, false),
	"MIT-STYLE":            licence(expr.MIT, false),
	"MPL-1":                licence(expr.MPL10, false),
	"MPL-1.0":              licence(expr.MPL10, false),
	"MPL-1.1":              licence(expr.MPL11, false),
	"MPL-2":                licence(expr.MPL20, false),
	"MPL-2.0":              licence(expr.MPL20, false),
	"MS-PL":                licence(expr.MSPL, false),
	"NCSA":                 licence(expr.NCSA, false),
	"NPL-1.0":              licence(expr.NPL10, false),
	"NPL-1.1":              licence(expr.NPL11, false),
	"OFL-1.1":              licence(expr.OFL11, false),
	"OPENSSL":              licence(expr.OpenSSL, false),
	"OPENVISION":           licence(expr.OpenVision, false),
	"OSL-1":                licence(expr.OSL10, false),
	"OSL-1.0":              licence(expr.OSL10, false),
	"OSL-1.1":              licence(expr.OSL11, false),
	"OSL-2":                licence(expr.OSL20, false),
	"OSL-2.0":              licence(expr.OSL20, false),
	"OSL-2.1":              licence(expr.OSL21, false),
	"OSL-3":                licence(expr.OSL30, false),
	"OSL-3.0":              licence(expr.OSL30, false),
	"PHP-3.0":              licence(expr.PHP30, false),
	"PHP-3.01":             licence(expr.PHP301, false),
	"PIL":                  licence(expr.PIL, false),
	"POSTGRESQL":           licence(expr.PostgreSQL, false),
	"PYTHON-2":             licence(expr.Python20, false),
	"PYTHON-2.0":           licence(expr.Python20, false),
	"PYTHON-2.0-COMPLETE":  licence(expr.Python20complete, false),
	"QPL-1":                licence(expr.QPL10, false),
	"QPL-1.0":              licence(expr.QPL10, false),
	"RUBY":                 licence(expr.Ruby, false),
	"SGI-B-1.0":            licence(expr.SGIB10, false),
	"SGI-B-1.1":            licence(expr.SGIB11, false),
	"SGI-B-2.0":            licence(expr.SGIB20, false),
	"SISSL":                licence(expr.SISSL, false),
	"SISSL-1.2":            licence(expr.SISSL12, false),
	"SLEEPYCAT":            licence(expr.Sleepycat, false),
	"UNICODE-DFS-2015":     licence(expr.UnicodeDFS2015, false),
	"UNICODE-DFS-2016":     licence(expr.UnicodeDFS2016, false),
	"UNICODE-TOU":          licence(expr.UnicodeTOU, false),
	"UNLICENSE":            licence(expr.Unlicense, false),
	"UNLICENSED":           licence(expr.Unlicense, false),
	"UPL-1":                licence(expr.UPL10, false),
	"UPL-1.0":              licence(expr.UPL10, false),
	"W3C":                  licence(expr.W3C, false),
	"W3C-19980720":         licence(expr.W3C19980720, false),
	"W3C-20150513":         licence(expr.W3C20150513, false),
	"W3CL":                 licence(expr.W3C, false),
	"WTF":                  licence(expr.WTFPL, false),
	"WTFPL":                licence(expr.WTFPL, false),
	"X11":                  licence(expr.X11, false),
	"XNET":                 licence(expr.Xnet, false),
	"ZEND-2":               licence(expr.Zend20, false),
	"ZEND-2.0":             licence(expr.Zend20, false),
	"ZLIB":                 licence(expr.Zlib, false),
	"ZLIB-ACKNOWLEDGEMENT": licence(expr.ZlibAcknowledgement, false),
	"ZOPE-1.1":             licence(expr.ZPL11, false),
	"ZOPE-2.0":             licence(expr.ZPL20, false),
	"ZOPE-2.1":             licence(expr.ZPL21, false),
	"ZPL-1.1":              licence(expr.ZPL11, false),
	"ZPL-2.0":              licence(expr.ZPL20, false),
	"ZPL-2.1":              licence(expr.ZPL21, false),

	// Non simple declared mappings
	// modified from https://github.com/oss-review-toolkit/ort/blob/fc5389c2cfd9c8b009794c8a11f5c91321b7a730/utils/spdx/src/main/resources/declared-license-mapping.yml

	// Ambiguous declared mappings (mapping reason not obvious without additional information)
	"ACADEMIC FREE LICENSE (AFL)":                         licence(expr.AFL21, false),
	"APACHE SOFTWARE LICENSES":                            licence(expr.Apache20, false),
	"APACHE SOFTWARE":                                     licence(expr.Apache20, false),
	"APPLE PUBLIC SOURCE":                                 licence(expr.APSL10, false),
	"BSD SOFTWARE":                                        licence(expr.BSD2Clause, false),
	"BSD STYLE":                                           licence(expr.BSD3Clause, false),
	"COMMON DEVELOPMENT AND DISTRIBUTION":                 licence(expr.CDDL10, false),
	"CREATIVE COMMONS - BY":                               licence(expr.CCBY30, false),
	"CREATIVE COMMONS ATTRIBUTION":                        licence(expr.CCBY30, false),
	"CREATIVE COMMONS":                                    licence(expr.CCBY30, false),
	"ECLIPSE PUBLIC LICENSE (EPL)":                        licence(expr.EPL10, false),
	"GENERAL PUBLIC LICENSE (GPL)":                        licence(expr.GPL20, true),
	"GNU FREE DOCUMENTATION LICENSE (FDL)":                licence(expr.GFDL13, true),
	"GNU GENERAL PUBLIC LIBRARY":                          licence(expr.GPL30, true),
	"GNU GENERAL PUBLIC LICENSE (GPL)":                    licence(expr.GPL30, true),
	"GNU GPL":                                             licence(expr.GPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)":            licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC":                           licence(expr.LGPL21, false),
	"GNU LESSER PUBLIC":                                   licence(expr.LGPL21, false),
	"GNU LESSER":                                          licence(expr.LGPL21, false),
	"GNU LGPL":                                            licence(expr.LGPL21, false),
	"GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE (LGPL)": licence(expr.LGPL21, false),
	"GNU PUBLIC":                                          licence(expr.GPL20, true),
	"GPL (WITH DUAL LICENSING OPTION)":                    licence(expr.GPL20, false),
	"GPLV2 WITH EXCEPTIONS":                               licence(expr.GPL20withclasspathexception, false),
	"INDIVIDUAL BSD":                                      licence(expr.BSD3Clause, false),
	"LESSER GENERAL PUBLIC LICENSE (LGPL)":                licence(expr.LGPL21, true),
	"LGPL WITH EXCEPTIONS":                                licence(expr.LGPL30, false),
	"LPGL, SEE LICENSE FILE.":                             licence(expr.LGPL30, true),
	"MOZILLA PUBLIC":                                      licence(expr.MPL20, false),
	"ZOPE PUBLIC":                                         licence(expr.ZPL21, false),

	// Non-ambiguous declared mappings
	"(NEW) BSD":                             licence(expr.BSD3Clause, false),
	"2-CLAUSE BSD":                          licence(expr.BSD2Clause, false),
	"2-CLAUSE BSDL":                         licence(expr.BSD2Clause, false),
	"3-CLAUSE BDSL":                         licence(expr.BSD3Clause, false),
	"3-CLAUSE BSD":                          licence(expr.BSD3Clause, false),
	"ACADEMIC FREE LICENSE (AFL-2.1":        licence(expr.AFL21, false),
	"AFFERO GENERAL PUBLIC LICENSE (AGPL-3": licence(expr.AGPL30, false),
	"APACHE 2 STYLE":                        licence(expr.Apache20, false),
	"APACHE LICENSE, ASL-2.0":               licence(expr.Apache20, false),
	"APACHE LICENSE, VERSION 2.0 (HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0": licence(expr.Apache20, false),
	"APACHE PUBLIC-1.1":                                  licence(expr.Apache11, false),
	"APACHE PUBLIC-2":                                    licence(expr.Apache20, false),
	"APACHE PUBLIC-2.0":                                  licence(expr.Apache20, false),
	"APACHE SOFTWARE LICENSE (APACHE-2":                  licence(expr.Apache20, false),
	"APACHE SOFTWARE LICENSE (APACHE-2.0":                licence(expr.Apache20, false),
	"APACHE SOFTWARE-1.1":                                licence(expr.Apache11, false),
	"APACHE SOFTWARE-2":                                  licence(expr.Apache20, false),
	"APACHE SOFTWARE-2.0":                                licence(expr.Apache20, false),
	"APACHE VERSION 2.0, JANUARY 2004":                   licence(expr.Apache20, false),
	"APACHE-2.0 */ &#39; &QUOT; &#X3D;END --":            licence(expr.Apache20, false),
	"BERKELEY SOFTWARE DISTRIBUTION (BSD)":               licence(expr.BSD2Clause, false),
	"BOOST SOFTWARE LICENSE 1.0 (BSL-1.0":                licence(expr.BSL10, false),
	"BOOST SOFTWARE":                                     licence(expr.BSL10, false),
	"BOUNCY CASTLE":                                      licence(expr.MIT, false),
	"BSD (3-CLAUSE)":                                     licence(expr.BSD3Clause, false),
	"BSD - SEE NDG/HTTPSCLIENT/LICENSE FILE FOR DETAILS": licence(expr.BSD3Clause, false),
	"BSD 2 CLAUSE":                                       licence(expr.BSD2Clause, false),
	"BSD 2-CLAUSE":                                       licence(expr.BSD2Clause, false),
	"BSD 3 CLAUSE":                                       licence(expr.BSD3Clause, false),
	"BSD 3-CLAUSE NEW":                                   licence(expr.BSD3Clause, false),
	"BSD 3-CLAUSE \"NEW\" OR \"REVISED\" LICENSE (BSD-3-CLAUSE)": licence(expr.BSD3Clause, false),
	"BSD 3-CLAUSE":            licence(expr.BSD3Clause, false),
	"BSD 4 CLAUSE":            licence(expr.BSD4Clause, false),
	"BSD 4-CLAUSE":            licence(expr.BSD4Clause, false),
	"BSD FOUR CLAUSE":         licence(expr.BSD4Clause, false),
	"BSD LICENSE FOR HSQL":    licence(expr.BSD3Clause, false),
	"BSD NEW":                 licence(expr.BSD3Clause, false),
	"BSD THREE CLAUSE":        licence(expr.BSD3Clause, false),
	"BSD TWO CLAUSE":          licence(expr.BSD2Clause, false),
	"BSD-3 CLAUSE":            licence(expr.BSD3Clause, false),
	"BSD-STYLE + ATTRIBUTION": licence(expr.BSD3ClauseAttribution, false),
	"CC BY-NC-SA-2.0":         licence(expr.CCBYNCSA20, false),
	"CC BY-NC-SA-2.5":         licence(expr.CCBYNCSA25, false),
	"CC BY-NC-SA-3.0":         licence(expr.CCBYNCSA30, false),
	"CC BY-NC-SA-4.0":         licence(expr.CCBYNCSA40, false),
	"CC BY-SA-2.0":            licence(expr.CCBYSA20, false),
	"CC BY-SA-2.5":            licence(expr.CCBYSA25, false),
	"CC BY-SA-3.0":            licence(expr.CCBYSA30, false),
	"CC BY-SA-4.0":            licence(expr.CCBYSA40, false),
	"CC0 1.0 UNIVERSAL (CC0 1.0) PUBLIC DOMAIN DEDICATION": licence(expr.CC010, false),
	"CC0 1.0 UNIVERSAL": licence(expr.CC010, false),
	"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)-1.0":    licence(expr.CDDL10, false),
	"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)-1.1":    licence(expr.CDDL11, false),
	"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.0 (CDDL-1.0": licence(expr.CDDL10, false),
	"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.1 (CDDL-1.1": licence(expr.CDDL11, false),
	"COMMON PUBLIC":     licence(expr.CPL10, false),
	"COMMON PUBLIC-1.0": licence(expr.CPL10, false),
	"CREATIVE COMMONS - ATTRIBUTION 4.0 INTERNATIONAL":                                    licence(expr.CCBY40, false),
	"CREATIVE COMMONS 3.0 BY-SA":                                                          licence(expr.CCBYSA30, false),
	"CREATIVE COMMONS ATTRIBUTION 3.0 UNPORTED (CC BY-3.0":                                licence(expr.CCBY30, false),
	"CREATIVE COMMONS ATTRIBUTION 4.0 INTERNATIONAL (CC BY-4.0":                           licence(expr.CCBY40, false),
	"CREATIVE COMMONS ATTRIBUTION 4.0 INTERNATIONAL PUBLIC":                               licence(expr.CCBY40, false),
	"CREATIVE COMMONS ATTRIBUTION-1.0":                                                    licence(expr.CCBY10, false),
	"CREATIVE COMMONS ATTRIBUTION-2.5":                                                    licence(expr.CCBY25, false),
	"CREATIVE COMMONS ATTRIBUTION-3.0":                                                    licence(expr.CCBY30, false),
	"CREATIVE COMMONS ATTRIBUTION-4.0":                                                    licence(expr.CCBY40, false),
	"CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL 4.0 INTERNATIONAL":                        licence(expr.CCBYNC40, false),
	"CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-NODERIVATIVES 4.0 INTERNATIONAL":          licence(expr.CCBYNCND40, false),
	"CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 3.0 UNPORTED (CC BY-NC-SA-3.0": licence(expr.CCBYNCSA30, false),
	"CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 4.0 INTERNATIONAL PUBLIC":      licence(expr.CCBYNCSA40, false),
	"CREATIVE COMMONS CC0":                                                                licence(expr.CC010, false),
	"CREATIVE COMMONS GNU LGPL-2.1":                                                       licence(expr.LGPL21, false),
	"CREATIVE COMMONS LICENSE ATTRIBUTION-NODERIVS 3.0 UNPORTED":                          licence(expr.CCBYNCND30, false),
	"CREATIVE COMMONS LICENSE ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 3.0 UNPORTED":          licence(expr.CCBYNCSA30, false),
	"CREATIVE COMMONS ZERO":                                                               licence(expr.CC010, false),
	"CREATIVE COMMONS-3.0":                                                                licence(expr.CCBY30, false),
	"ECLIPSE DISTRIBUTION LICENSE (EDL)-1.0":                                              licence(expr.BSD3Clause, false),
	"ECLIPSE DISTRIBUTION LICENSE (NEW BSD LICENSE)":                                      licence(expr.BSD3Clause, false),
	"ECLIPSE DISTRIBUTION-1.0":                                                            licence(expr.BSD3Clause, false),
	"ECLIPSE PUBLIC LICENSE (EPL)-1.0":                                                    licence(expr.EPL10, false),
	"ECLIPSE PUBLIC LICENSE (EPL)-2.0":                                                    licence(expr.EPL20, false),
	"ECLIPSE PUBLIC LICENSE 1.0 (EPL-1.0":                                                 licence(expr.EPL10, false),
	"ECLIPSE PUBLIC LICENSE 2.0 (EPL-2.0":                                                 licence(expr.EPL20, false),
	"ECLIPSE PUBLIC":                                                                      licence(expr.EPL10, false),
	"ECLIPSE PUBLIC-1.0":                                                                  licence(expr.EPL10, false),
	"ECLIPSE PUBLIC-2.0":                                                                  licence(expr.EPL20, false),
	"ECLIPSE PUBLISH-1.0":                                                                 licence(expr.EPL10, false),
	"EPL (ECLIPSE PUBLIC LICENSE)-1.0":                                                    licence(expr.EPL10, false),
	"EU PUBLIC LICENSE 1.0 (EUPL-1.0":                                                     licence(expr.EUPL10, false),
	"EU PUBLIC LICENSE 1.1 (EUPL-1.1":                                                     licence(expr.EUPL11, false),
	"EUROPEAN UNION PUBLIC LICENSE (EUPL-1.0":                                             licence(expr.EUPL10, false),
	"EUROPEAN UNION PUBLIC LICENSE (EUPL-1.1":                                             licence(expr.EUPL11, false),
	"EUROPEAN UNION PUBLIC LICENSE 1.0 (EUPL-1.0":                                         licence(expr.EUPL10, false),
	"EUROPEAN UNION PUBLIC LICENSE 1.1 (EUPL-1.1":                                         licence(expr.EUPL11, false),
	"EUROPEAN UNION PUBLIC-1.0":                                                           licence(expr.EUPL10, false),
	"EUROPEAN UNION PUBLIC-1.1":                                                           licence(expr.EUPL11, false),
	"EXPAT (MIT/X11)":                                                                     licence(expr.MIT, false),
	"GENERAL PUBLIC LICENSE 2.0 (GPL)":                                                    licence(expr.GPL20, false),
	"GNU AFFERO GENERAL PUBLIC LICENSE V3 (AGPL-3":                                        licence(expr.AGPL30, false),
	"GNU AFFERO GENERAL PUBLIC LICENSE V3 (AGPL-3.0":                                      licence(expr.AGPL30, false),
	"GNU AFFERO GENERAL PUBLIC LICENSE V3 OR LATER (AGPL3+)":                              licence(expr.AGPL30, true),
	"GNU AFFERO GENERAL PUBLIC LICENSE V3 OR LATER (AGPLV3+)":                             licence(expr.AGPL30, true),
	"GNU AFFERO GENERAL PUBLIC-3":                                                         licence(expr.AGPL30, false),
	"GNU FREE DOCUMENTATION LICENSE (GFDL-1.3":                                            licence(expr.GFDL13, false),
	"GNU GENERAL LESSER PUBLIC LICENSE (LGPL)-2.1":                                        licence(expr.LGPL21, false),
	"GNU GENERAL LESSER PUBLIC LICENSE (LGPL)-3.0":                                        licence(expr.LGPL30, false),
	"GNU GENERAL PUBLIC LICENSE (GPL), VERSION 2, WITH CLASSPATH EXCEPTION":               licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE (GPL), VERSION 2, WITH THE CLASSPATH EXCEPTION":           licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE (GPL)-2":                                                  licence(expr.GPL20, false),
	"GNU GENERAL PUBLIC LICENSE (GPL)-3":                                                  licence(expr.GPL30, false),
	"GNU GENERAL PUBLIC LICENSE V2 (GPL-2":                                                licence(expr.GPL20, false),
	"GNU GENERAL PUBLIC LICENSE V2 OR LATER (GPLV2+)":                                     licence(expr.GPL20, true),
	"GNU GENERAL PUBLIC LICENSE V2.0 ONLY, WITH CLASSPATH EXCEPTION":                      licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE V3 (GPL-3":                                                licence(expr.GPL30, false),
	"GNU GENERAL PUBLIC LICENSE V3 OR LATER (GPLV3+)":                                     licence(expr.GPL30, true),
	"GNU GENERAL PUBLIC LICENSE VERSION 2 (GPL-2":                                         licence(expr.GPL20, false),
	"GNU GENERAL PUBLIC LICENSE VERSION 2, JUNE 1991":                                     licence(expr.GPL20, false),
	"GNU GENERAL PUBLIC LICENSE VERSION 3 (GPL-3":                                         licence(expr.GPL30, false),
	"GNU GENERAL PUBLIC LICENSE, VERSION 2 (GPL2), WITH THE CLASSPATH EXCEPTION":          licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE, VERSION 2 WITH THE CLASSPATH EXCEPTION":                  licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE, VERSION 2 WITH THE GNU CLASSPATH EXCEPTION":              licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC LICENSE, VERSION 2, WITH THE CLASSPATH EXCEPTION":                 licence(expr.GPL20withclasspathexception, false),
	"GNU GENERAL PUBLIC-2":                                                                licence(expr.GPL20, false),
	"GNU GENERAL PUBLIC-3":                                                                licence(expr.GPL30, false),
	"GNU GPL-2":                                                                           licence(expr.GPL20, false),
	"GNU GPL-3":                                                                           licence(expr.GPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2":                                          licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2.0":                                        licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2.1":                                        licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-3":                                          licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-3.0":                                        licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2":                                           licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2.0":                                         licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2.1":                                         licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL-3":                                           licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE (LGPL-3.0":                                         licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE V2 (LGPL-2":                                        licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC LICENSE V2 OR LATER (LGPLV2+)":                             licence(expr.LGPL20, true),
	"GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPL-3":                                        licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC LICENSE V3 OR LATER (LGPLV3+)":                             licence(expr.LGPL30, true),
	"GNU LESSER GENERAL PUBLIC LICENSE VERSION 2.1 (LGPL-2.1":                             licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC LICENSE VERSION 2.1, FEBRUARY 1999":                        licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC LICENSE, VERSION 2.1, FEBRUARY 1999":                       licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC-2":                                                         licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC-2.0":                                                       licence(expr.LGPL20, false),
	"GNU LESSER GENERAL PUBLIC-2.1":                                                       licence(expr.LGPL21, false),
	"GNU LESSER GENERAL PUBLIC-3":                                                         licence(expr.LGPL30, false),
	"GNU LESSER GENERAL PUBLIC-3.0":                                                       licence(expr.LGPL30, false),
	"GNU LGP (GNU GENERAL PUBLIC LICENSE)-2":                                              licence(expr.LGPL20, false),
	"GNU LGPL (GNU LESSER GENERAL PUBLIC LICENSE)-2.1":                                    licence(expr.LGPL21, false),
	"GNU LGPL-2":                     licence(expr.LGPL20, false),
	"GNU LGPL-2.0":                   licence(expr.LGPL20, false),
	"GNU LGPL-2.1":                   licence(expr.LGPL21, false),
	"GNU LGPL-3":                     licence(expr.LGPL30, false),
	"GNU LGPL-3.0":                   licence(expr.LGPL30, false),
	"GNU LIBRARY GENERAL PUBLIC-2.0": licence(expr.LGPL20, false),
	"GNU LIBRARY GENERAL PUBLIC-2.1": licence(expr.LGPL21, false),
	"GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 2.0 (LGPL-2": licence(expr.LGPL20, false),
	"GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 3.0 (LGPL-3": licence(expr.LGPL30, false),
	"GPL (≥ 3)":                                                             licence(expr.GPL30, true),
	"GPL 2 WITH CLASSPATH EXCEPTION":                                        licence(expr.GPL20withclasspathexception, false),
	"GPL V2 WITH CLASSPATH EXCEPTION":                                       licence(expr.GPL20withclasspathexception, false),
	"GPL-2+ WITH AUTOCONF EXCEPTION":                                        licence(expr.GPL20withautoconfexception, true),
	"GPL-3+ WITH AUTOCONF EXCEPTION":                                        licence(expr.GPL30withautoconfexception, true),
	"GPL2 W/ CPE":                                                           licence(expr.GPL20withclasspathexception, false),
	"GPLV2 LICENSE, INCLUDES THE CLASSPATH EXCEPTION":                       licence(expr.GPL20withclasspathexception, false),
	"GPLV2 WITH CLASSPATH EXCEPTION":                                        licence(expr.GPL20withclasspathexception, false),
	"HSQLDB LICENSE, A BSD OPEN SOURCE":                                     licence(expr.BSD3Clause, false),
	"HTTP://ANT-CONTRIB.SOURCEFORGE.NET/TASKS/LICENSE.TXT":                  licence(expr.Apache11, false),
	"HTTP://ASM.OW2.ORG/LICENSE.HTML":                                       licence(expr.BSD3Clause, false),
	"HTTP://CREATIVECOMMONS.ORG/PUBLICDOMAIN/ZERO/1.0/LEGALCODE":            licence(expr.CC010, false),
	"HTTP://EN.WIKIPEDIA.ORG/WIKI/ZLIB_LICENSE":                             licence(expr.Zlib, false),
	"HTTP://JSON.CODEPLEX.COM/LICENSE":                                      licence(expr.MIT, false),
	"HTTP://POLYMER.GITHUB.IO/LICENSE.TXT":                                  licence(expr.BSD3Clause, false),
	"HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0":                            licence(expr.Apache20, false),
	"HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0.HTML":                       licence(expr.Apache20, false),
	"HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0.TXT":                        licence(expr.Apache20, false),
	"HTTP://WWW.GNU.ORG/COPYLEFT/LESSER.HTML":                               licence(expr.LGPL30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/1.0":                     licence(expr.CCBYNCND10, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/2.0":                     licence(expr.CCBYNCND20, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/2.5":                     licence(expr.CCBYNCND25, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/3.0":                     licence(expr.CCBYNCND30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/4.0":                     licence(expr.CCBYNCND40, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/1.0":                     licence(expr.CCBYNCSA10, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/2.0":                     licence(expr.CCBYNCSA20, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/2.5":                     licence(expr.CCBYNCSA25, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/3.0":                     licence(expr.CCBYNCSA30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/4.0":                     licence(expr.CCBYNCSA40, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/1.0":                        licence(expr.CCBYND10, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/2.0":                        licence(expr.CCBYND20, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/2.5":                        licence(expr.CCBYND25, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/3.0":                        licence(expr.CCBYND30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/4.0":                        licence(expr.CCBYND40, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/1.0":                        licence(expr.CCBYSA10, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/2.0":                        licence(expr.CCBYSA20, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/2.5":                        licence(expr.CCBYSA25, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/3.0":                        licence(expr.CCBYSA30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/4.0":                        licence(expr.CCBYSA40, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/1.0":                           licence(expr.CCBY10, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/2.0":                           licence(expr.CCBY20, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/2.5":                           licence(expr.CCBY25, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/3.0":                           licence(expr.CCBY30, false),
	"HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/4.0":                           licence(expr.CCBY40, false),
	"HTTPS://CREATIVECOMMONS.ORG/PUBLICDOMAIN/ZERO/1.0/":                    licence(expr.CC010, false),
	"HTTPS://GITHUB.COM/DOTNET/CORE-SETUP/BLOB/MASTER/LICENSE.TXT":          licence(expr.MIT, false),
	"HTTPS://GITHUB.COM/DOTNET/COREFX/BLOB/MASTER/LICENSE.TXT":              licence(expr.MIT, false),
	"HTTPS://RAW.GITHUB.COM/RDFLIB/RDFLIB/MASTER/LICENSE":                   licence(expr.BSD3Clause, false),
	"HTTPS://RAW.GITHUBUSERCONTENT.COM/ASPNET/ASPNETCORE/2.0.0/LICENSE.TXT": licence(expr.Apache20, false),
	"HTTPS://RAW.GITHUBUSERCONTENT.COM/ASPNET/HOME/2.0.0/LICENSE.TXT":       licence(expr.Apache20, false),
	"HTTPS://RAW.GITHUBUSERCONTENT.COM/NUGET/NUGET.CLIENT/DEV/LICENSE.TXT":  licence(expr.Apache20, false),
	"HTTPS://WWW.APACHE.ORG/LICENSES/LICENSE-2.0":                           licence(expr.Apache20, false),
	"HTTPS://WWW.ECLIPSE.ORG/LEGAL/EPL-V10.HTML":                            licence(expr.EPL10, false),
	"HTTPS://WWW.ECLIPSE.ORG/LEGAL/EPL-V20.HTML":                            licence(expr.EPL20, false),
	"IBM PUBLIC":         licence(expr.IPL10, false),
	"ISC LICENSE (ISCL)": licence(expr.ISC, false),
	"JYTHON SOFTWARE":    licence(expr.Python20, false),
	"KIRKK.COM BSD":      licence(expr.BSD3Clause, false),
	"LESSER GENERAL PUBLIC LICENSE, VERSION 3 OR GREATER":                              licence(expr.LGPL30, true),
	"LICENSE AGREEMENT FOR OPEN SOURCE COMPUTER VISION LIBRARY (3-CLAUSE BSD LICENSE)": licence(expr.BSD3Clause, false),
	"MIT (HTTP://MOOTOOLS.NET/LICENSE.TXT)":                                            licence(expr.MIT, false),
	"MIT / HTTP://REM.MIT-LICENSE.ORG":                                                 licence(expr.MIT, false),
	"MIT LICENSE (HTTP://OPENSOURCE.ORG/LICENSES/MIT)":                                 licence(expr.MIT, false),
	"MIT LICENSE (MIT)": licence(expr.MIT, false),
	"MIT LICENSE(MIT)":  licence(expr.MIT, false),
	"MIT LICENSED. HTTP://WWW.OPENSOURCE.ORG/LICENSES/MIT-LICENSE.PHP": licence(expr.MIT, false),
	"MIT/EXPAT": licence(expr.MIT, false),
	"MOCKRUNNER LICENSE, BASED ON APACHE SOFTWARE-1.1": licence(expr.Apache11, false),
	"MODIFIED BSD":                        licence(expr.BSD3Clause, false),
	"MOZILLA PUBLIC LICENSE 1.0 (MPL)":    licence(expr.MPL10, false),
	"MOZILLA PUBLIC LICENSE 1.1 (MPL-1.1": licence(expr.MPL11, false),
	"MOZILLA PUBLIC LICENSE 2.0 (MPL-2.0": licence(expr.MPL20, false),
	"MOZILLA PUBLIC-1.0":                  licence(expr.MPL10, false),
	"MOZILLA PUBLIC-1.1":                  licence(expr.MPL11, false),
	"MOZILLA PUBLIC-2.0":                  licence(expr.MPL20, false),
	"NCSA OPEN SOURCE":                    licence(expr.NCSA, false),
	"NETSCAPE PUBLIC LICENSE (NPL)":       licence(expr.NPL10, false),
	"NETSCAPE PUBLIC":                     licence(expr.NPL10, false),
	"NEW BSD":                             licence(expr.BSD3Clause, false),
	"OPEN SOFTWARE LICENSE 3.0 (OSL-3.0":  licence(expr.OSL30, false),
	"OPEN SOFTWARE-3.0":                   licence(expr.OSL30, false),
	"PERL ARTISTIC-2":                     licence(expr.Artistic10Perl, false),
	// Note: public domain without a specific license should not be mapped
	// see https://wiki.spdx.org/view/Legal_Team/Decisions/Dealing_with_Public_Domain_within_SPDX_Files
	// and https://opensource.google/documentation/reference/thirdparty/licenses#unencumbered
	"PUBLIC DOMAIN (CC0-1.0)":                       licence(expr.CC010, false),
	"PUBLIC DOMAIN, PER CREATIVE COMMONS CC0":       licence(expr.CC010, false),
	"QT PUBLIC LICENSE (QPL)":                       licence(expr.QPL10, false),
	"QT PUBLIC":                                     licence(expr.QPL10, false),
	"REVISED BSD":                                   licence(expr.BSD3Clause, false),
	"RUBY'S":                                        licence(expr.Ruby, false),
	"SEQUENCE LIBRARY LICENSE (BSD-LIKE)":           licence(expr.BSD3Clause, false),
	"SIL OPEN FONT LICENSE 1.1 (OFL-1.1":            licence(expr.OFL11, false),
	"SIL OPEN FONT-1.1":                             licence(expr.OFL11, false),
	"SIMPLIFIED BSD LISCENCE":                       licence(expr.BSD2Clause, false),
	"SIMPLIFIED BSD":                                licence(expr.BSD2Clause, false),
	"SUN INDUSTRY STANDARDS SOURCE LICENSE (SISSL)": licence(expr.SISSL, false),
	"THREE-CLAUSE BSD-STYLE":                        licence(expr.BSD3Clause, false),
	"TWO-CLAUSE BSD-STYLE":                          licence(expr.BSD2Clause, false),
	"UNIVERSAL PERMISSIVE LICENSE (UPL)":            licence(expr.UPL10, false),
	"UNIVERSAL PERMISSIVE-1.0":                      licence(expr.UPL10, false),
	"UNLICENSE (UNLICENSE)":                         licence(expr.Unlicense, false),
	"W3C SOFTWARE":                                  licence(expr.W3C, false),
	"ZLIB / LIBPNG":                                 licence(expr.ZlibAcknowledgement, false),
	"ZLIB/LIBPNG":                                   licence(expr.ZlibAcknowledgement, false),
	"['MIT']":                                       licence(expr.MIT, false),
}

const (
	LicenseTextPrefix   = "text://"
	LicenseFilePrefix   = "file://"
	CustomLicensePrefix = "CUSTOM License"
)

// pythonLicenseExceptions contains licenses that we cannot separate correctly using our logic.
// first word after separator (or/and) => license name
var pythonLicenseExceptions = map[string]string{
	"lesser":       "GNU Library or Lesser General Public License (LGPL)",
	"distribution": "Common Development and Distribution License 1.0 (CDDL-1.0)",
	"disclaimer":   "Historical Permission Notice and Disclaimer (HPND)",
}

// Split licenses without considering "and"/"or"
// examples:
// 'GPL-1+,GPL-2' => {"GPL-1+", "GPL-2"}
// 'GPL-1+ or Artistic or Artistic-dist' => {"GPL-1+", "Artistic", "Artistic-dist"}
// 'LGPLv3+_or_GPLv2+' => {"LGPLv3+", "GPLv2"}
// 'BSD-3-CLAUSE and GPL-2' => {"BSD-3-CLAUSE", "GPL-2"}
// 'GPL-1+ or Artistic, and BSD-4-clause-POWERDOG' => {"GPL-1+", "Artistic", "BSD-4-clause-POWERDOG"}
// 'BSD 3-Clause License or Apache License, Version 2.0' => {"BSD 3-Clause License", "Apache License, Version 2.0"}
var licenseSplitRegexp = regexp.MustCompile("(,?[_ ]+(?:or|and)[_ ]+)|(,[ ]*)")

// Typical keywords for license texts
var licenseTextKeywords = []string{
	"http://",
	"https://",
	"(c)",
	"as-is",
	";",
	"hereby",
	"permission to use",
	"permission is",
	"use in source",
	"use, copy, modify",
	"using",
}

func isLicenseText(str string) bool {
	for _, keyword := range licenseTextKeywords {
		if strings.Contains(str, keyword) {
			return true
		}
	}
	return false
}

func TrimLicenseText(text string) string {
	s := strings.Split(text, " ")
	n := len(s)
	if n > 3 {
		n = 3
	}
	return strings.Join(s[:n], " ") + "..."
}

// version number match
var versionRegexpString = "([A-UW-Z)])( LICENSE)?\\s*[,(-]?\\s*(V|V\\.|VER|VER\\.|VERSION|VERSION-|-)?\\s*([1-9](\\.\\d)*)[)]?"

// case insensitive version match anywhere in string
var versionRegexp = regexp.MustCompile("(?i)" + versionRegexpString)

// version suffix match
var versionSuffixRegexp = regexp.MustCompile(versionRegexpString + "$")

// suffixes from https://spdx.dev/learn/handling-license-info/
var onlySuffixes = [2]string{"-ONLY", " ONLY"}
var plusSuffixes = [3]string{"+", "-OR-LATER", " OR LATER"}

func standardizeKeyAndSuffix(name string) expr.SimpleExpr {
	// Standardize space, including newline
	name = strings.Join(strings.Fields(name), " ")
	name = strings.ToUpper(name)
	// Do not perform any further normalization for URLs
	if strings.HasPrefix(name, "HTTP") {
		return expr.SimpleExpr{License: name, HasPlus: false}
	}
	name = strings.ReplaceAll(name, "LICENCE", "LICENSE")
	name = strings.TrimPrefix(name, "THE ")
	name = strings.TrimSuffix(name, " LICENSE")
	name = strings.TrimSuffix(name, " LICENSED")
	name = strings.TrimSuffix(name, "-LICENSE")
	name = strings.TrimSuffix(name, "-LICENSED")
	// Remove License and Licensed suffixes except for licenses already containing those suffixes such as Unlicense
	if name != "UNLICENSE" {
		name = strings.TrimSuffix(name, "LICENSE")
	}
	if name != "UNLICENSED" {
		name = strings.TrimSuffix(name, "LICENSED")
	}
	hasPlus := false
	for _, s := range plusSuffixes {
		if strings.HasSuffix(name, s) {
			name = strings.TrimSuffix(name, s)
			hasPlus = true
		}
	}
	for _, s := range onlySuffixes {
		name = strings.TrimSuffix(name, s)
	}
	name = versionSuffixRegexp.ReplaceAllString(name, "$1-$4")
	return expr.SimpleExpr{License: name, HasPlus: hasPlus}
}

func Normalize(name string) string {
	return NormalizeLicense(name).String()
}

func NormalizeLicense(name string) expr.SimpleExpr {
	// Always trim leading and trailing spaces, even if we don't find this license in `mapping`.
	name = strings.TrimSpace(name)
	normalized := standardizeKeyAndSuffix(name)
	if found, ok := mapping[normalized.License]; ok {
		return expr.SimpleExpr{License: found.License, HasPlus: found.HasPlus || normalized.HasPlus}
	}
	return expr.SimpleExpr{License: name, HasPlus: false}
}

func SplitLicenses(str string) []string {
	if str == "" {
		return nil
	}
	if isLicenseText(strings.ToLower(str)) {
		return []string{
			LicenseTextPrefix + str,
		}
	}

	var licenses []string
	for _, maybeLic := range licenseSplitRegexp.Split(str, -1) {
		lower := strings.ToLower(maybeLic)
		firstWord, _, _ := strings.Cut(lower, " ")
		if len(licenses) > 0 {
			// e.g. `Apache License, Version 2.0`
			if firstWord == "ver" || firstWord == "version" {
				licenses[len(licenses)-1] += ", " + maybeLic
				continue
				// e.g. `GNU Lesser General Public License v2 or later (LGPLv2+)`
			} else if firstWord == "later" {
				licenses[len(licenses)-1] += " or " + maybeLic
				continue
			} else if lic, ok := pythonLicenseExceptions[firstWord]; ok {
				// Check `or` and `and` separators
				if lic == licenses[len(licenses)-1]+" or "+maybeLic || lic == licenses[len(licenses)-1]+" and "+maybeLic {
					licenses[len(licenses)-1] = lic
				}
				continue
			}
		}
		licenses = append(licenses, maybeLic)
	}
	return licenses
}

// Split license string considering spaces as separator
// e.g. MPL 2.0 GPL2+ => {"MPL2.0", "GPL2+"}
func LaxSplitLicenses(str string) []string {
	if str == "" {
		return nil
	}
	var licenses []string
	str = versionRegexp.ReplaceAllString(str, "$1-$4")
	for _, s := range strings.Fields(str) {
		s = strings.Trim(s, "()")
		switch {
		case s == "":
			continue
		case s == "AND" || s == "OR":
			continue
		default:
			licenses = append(licenses, Normalize(s))
		}
	}
	return licenses
}
