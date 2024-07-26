package licensing

import (
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

var mapping = make(map[string]expression.SimpleExpr)

func addMap(name, key string, hasPlus bool) {
	mapping[name] = expression.SimpleExpr{License: key, HasPlus: hasPlus}
}

func init() {
	// Simple mappings (i.e. that could be parsed by SpdxExpression.parse, at least without space)
	// modified from https://github.com/oss-review-toolkit/ort/blob/fc5389c2cfd9c8b009794c8a11f5c91321b7a730/utils/spdx/src/main/resources/simple-license-mapping.yml

	// Ambiguous simple mappings (mapping reason not obvious without additional information)
	addMap("AFL", expression.AFL30, false)
	addMap("AGPL", expression.AGPL30, false)
	addMap("AL-2", expression.Apache20, false)
	addMap("AL-2.0", expression.Apache20, false)
	addMap("APACHE", expression.Apache20, false)
	addMap("APACHE-STYLE", expression.Apache20, false)
	addMap("ARTISTIC", expression.Artistic20, false)
	addMap("ASL", expression.Apache20, false)
	addMap("BSD", expression.BSD3Clause, false)
	addMap("BSD*", expression.BSD3Clause, false)
	addMap("BSD-LIKE", expression.BSD3Clause, false)
	addMap("BSD-STYLE", expression.BSD3Clause, false)
	addMap("BSD-VARIANT", expression.BSD3Clause, false)
	addMap("CDDL", expression.CDDL10, false)
	addMap("ECLIPSE", expression.EPL10, false)
	addMap("EPL", expression.EPL10, false)
	addMap("EUPL", expression.EUPL10, false)
	addMap("FDL", expression.GFDL13, true)
	addMap("GFDL", expression.GFDL13, true)
	addMap("GPL", expression.GPL20, true)
	addMap("LGPL", expression.LGPL20, true)
	addMap("MPL", expression.MPL20, false)
	addMap("NETSCAPE", expression.NPL11, false)
	addMap("PYTHON", expression.Python20, false)
	addMap("ZOPE", expression.ZPL21, false)

	// Non-ambiguous simple mappings
	addMap("0BSD", expression.ZeroBSD, false)
	addMap("AFL-1.1", expression.AFL11, false)
	addMap("AFL-1.2", expression.AFL12, false)
	addMap("AFL-2", expression.AFL20, false)
	addMap("AFL-2.0", expression.AFL20, false)
	addMap("AFL-2.1", expression.AFL21, false)
	addMap("AFL-3.0", expression.AFL30, false)
	addMap("AGPL-1.0", expression.AGPL10, false)
	addMap("AGPL-3.0", expression.AGPL30, false)
	addMap("APACHE-1", expression.Apache10, false)
	addMap("APACHE-1.0", expression.Apache10, false)
	addMap("APACHE-1.1", expression.Apache11, false)
	addMap("APACHE-2", expression.Apache20, false)
	addMap("APACHE-2.0", expression.Apache20, false)
	addMap("APL-2", expression.Apache20, false)
	addMap("APL-2.0", expression.Apache20, false)
	addMap("APSL-1.0", expression.APSL10, false)
	addMap("APSL-1.1", expression.APSL11, false)
	addMap("APSL-1.2", expression.APSL12, false)
	addMap("APSL-2.0", expression.APSL20, false)
	addMap("ARTISTIC-1.0", expression.Artistic10, false)
	addMap("ARTISTIC-1.0-CL-8", expression.Artistic10cl8, false)
	addMap("ARTISTIC-1.0-PERL", expression.Artistic10Perl, false)
	addMap("ARTISTIC-2.0", expression.Artistic20, false)
	addMap("ASF-1", expression.Apache10, false)
	addMap("ASF-1.0", expression.Apache10, false)
	addMap("ASF-1.1", expression.Apache11, false)
	addMap("ASF-2", expression.Apache20, false)
	addMap("ASF-2.0", expression.Apache20, false)
	addMap("ASL-1", expression.Apache10, false)
	addMap("ASL-1.0", expression.Apache10, false)
	addMap("ASL-1.1", expression.Apache11, false)
	addMap("ASL-2", expression.Apache20, false)
	addMap("ASL-2.0", expression.Apache20, false)
	addMap("BCL", expression.BCL, false)
	addMap("BEERWARE", expression.Beerware, false)
	addMap("BOOST", expression.BSL10, false)
	addMap("BOOST-1.0", expression.BSL10, false)
	addMap("BOUNCY", expression.MIT, false)
	addMap("BSD-2", expression.BSD2Clause, false)
	addMap("BSD-2-CLAUSE", expression.BSD2Clause, false)
	addMap("BSD-2-CLAUSE-FREEBSD", expression.BSD2ClauseFreeBSD, false)
	addMap("BSD-2-CLAUSE-NETBSD", expression.BSD2ClauseNetBSD, false)
	addMap("BSD-3", expression.BSD3Clause, false)
	addMap("BSD-3-CLAUSE", expression.BSD3Clause, false)
	addMap("BSD-3-CLAUSE-ATTRIBUTION", expression.BSD3ClauseAttribution, false)
	addMap("BSD-3-CLAUSE-CLEAR", expression.BSD3ClauseClear, false)
	addMap("BSD-3-CLAUSE-LBNL", expression.BSD3ClauseLBNL, false)
	addMap("BSD-4", expression.BSD4Clause, false)
	addMap("BSD-4-CLAUSE", expression.BSD4Clause, false)
	addMap("BSD-4-CLAUSE-UC", expression.BSD4ClauseUC, false)
	addMap("BSD-PROTECTION", expression.BSDProtection, false)
	addMap("BSL", expression.BSL10, false)
	addMap("BSL-1.0", expression.BSL10, false)
	addMap("CC-BY-1.0", expression.CCBY10, false)
	addMap("CC-BY-2.0", expression.CCBY20, false)
	addMap("CC-BY-2.5", expression.CCBY25, false)
	addMap("CC-BY-3.0", expression.CCBY30, false)
	addMap("CC-BY-4.0", expression.CCBY40, false)
	addMap("CC-BY-NC-1.0", expression.CCBYNC10, false)
	addMap("CC-BY-NC-2.0", expression.CCBYNC20, false)
	addMap("CC-BY-NC-2.5", expression.CCBYNC25, false)
	addMap("CC-BY-NC-3.0", expression.CCBYNC30, false)
	addMap("CC-BY-NC-4.0", expression.CCBYNC40, false)
	addMap("CC-BY-NC-ND-1.0", expression.CCBYNCND10, false)
	addMap("CC-BY-NC-ND-2.0", expression.CCBYNCND20, false)
	addMap("CC-BY-NC-ND-2.5", expression.CCBYNCND25, false)
	addMap("CC-BY-NC-ND-3.0", expression.CCBYNCND30, false)
	addMap("CC-BY-NC-ND-4.0", expression.CCBYNCND40, false)
	addMap("CC-BY-NC-SA-1.0", expression.CCBYNCSA10, false)
	addMap("CC-BY-NC-SA-2.0", expression.CCBYNCSA20, false)
	addMap("CC-BY-NC-SA-2.5", expression.CCBYNCSA25, false)
	addMap("CC-BY-NC-SA-3.0", expression.CCBYNCSA30, false)
	addMap("CC-BY-NC-SA-4.0", expression.CCBYNCSA40, false)
	addMap("CC-BY-ND-1.0", expression.CCBYND10, false)
	addMap("CC-BY-ND-2.0", expression.CCBYND20, false)
	addMap("CC-BY-ND-2.5", expression.CCBYND25, false)
	addMap("CC-BY-ND-3.0", expression.CCBYND30, false)
	addMap("CC-BY-ND-4.0", expression.CCBYND40, false)
	addMap("CC-BY-SA-1.0", expression.CCBYSA10, false)
	addMap("CC-BY-SA-2.0", expression.CCBYSA20, false)
	addMap("CC-BY-SA-2.5", expression.CCBYSA25, false)
	addMap("CC-BY-SA-3.0", expression.CCBYSA30, false)
	addMap("CC-BY-SA-4.0", expression.CCBYSA40, false)
	addMap("CC0", expression.CC010, false)
	addMap("CC0-1.0", expression.CC010, false)
	addMap("CDDL-1", expression.CDDL10, false)
	addMap("CDDL-1.0", expression.CDDL10, false)
	addMap("CDDL-1.1", expression.CDDL11, false)
	addMap("COMMONS-CLAUSE", expression.CommonsClause, false)
	addMap("CPAL", expression.CPAL10, false)
	addMap("CPAL-1.0", expression.CPAL10, false)
	addMap("CPL", expression.CPL10, false)
	addMap("CPL-1.0", expression.CPL10, false)
	addMap("ECLIPSE-1.0", expression.EPL10, false)
	addMap("ECLIPSE-2.0", expression.EPL20, false)
	addMap("EDL-1.0", expression.BSD3Clause, false)
	addMap("EGENIX", expression.EGenix, false)
	addMap("EPL-1.0", expression.EPL10, false)
	addMap("EPL-2.0", expression.EPL20, false)
	addMap("EUPL-1.0", expression.EUPL10, false)
	addMap("EUPL-1.1", expression.EUPL11, false)
	addMap("EXPAT", expression.MIT, false)
	addMap("FACEBOOK-2-CLAUSE", expression.Facebook2Clause, false)
	addMap("FACEBOOK-3-CLAUSE", expression.Facebook3Clause, false)
	addMap("FACEBOOK-EXAMPLES", expression.FacebookExamples, false)
	addMap("FREEIMAGE", expression.FreeImage, false)
	addMap("FTL", expression.FTL, false)
	addMap("GFDL-1.1", expression.GFDL11, false)
	addMap("GFDL-1.1-INVARIANTS", expression.GFDL11WithInvariants, false)
	addMap("GFDL-1.1-NO-INVARIANTS", expression.GFDL11NoInvariants, false)
	addMap("GFDL-1.2", expression.GFDL12, false)
	addMap("GFDL-1.2-INVARIANTS", expression.GFDL12WithInvariants, false)
	addMap("GFDL-1.2-NO-INVARIANTS", expression.GFDL12NoInvariants, false)
	addMap("GFDL-1.3", expression.GFDL13, false)
	addMap("GFDL-1.3-INVARIANTS", expression.GFDL13WithInvariants, false)
	addMap("GFDL-1.3-NO-INVARIANTS", expression.GFDL13NoInvariants, false)
	addMap("GFDL-NIV-1.3", expression.GFDL13NoInvariants, false)
	addMap("GO", expression.BSD3Clause, false)
	addMap("GPL-1", expression.GPL10, false)
	addMap("GPL-1.0", expression.GPL10, false)
	addMap("GPL-2", expression.GPL20, false)
	addMap("GPL-2+-WITH-BISON-EXCEPTION", expression.GPL20withbisonexception, true)
	addMap("GPL-2.0", expression.GPL20, false)
	addMap("GPL-2.0-WITH-AUTOCONF-EXCEPTION", expression.GPL20withautoconfexception, false)
	addMap("GPL-2.0-WITH-BISON-EXCEPTION", expression.GPL20withbisonexception, false)
	addMap("GPL-2.0-WITH-CLASSPATH-EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GPL-2.0-WITH-FONT-EXCEPTION", expression.GPL20withfontexception, false)
	addMap("GPL-2.0-WITH-GCC-EXCEPTION", expression.GPL20withGCCexception, false)
	addMap("GPL-3", expression.GPL30, false)
	addMap("GPL-3+-WITH-BISON-EXCEPTION", expression.GPL20withbisonexception, true)
	addMap("GPL-3.0", expression.GPL30, false)
	addMap("GPL-3.0-WITH-AUTOCONF-EXCEPTION", expression.GPL30withautoconfexception, false)
	addMap("GPL-3.0-WITH-GCC-EXCEPTION", expression.GPL30withGCCexception, false)
	addMap("GPLV2+CE", expression.GPL20withclasspathexception, true)
	addMap("GUST-FONT", expression.GUSTFont, false)
	addMap("HSQLDB", expression.BSD3Clause, false)
	addMap("IMAGEMAGICK", expression.ImageMagick, false)
	addMap("IPL-1.0", expression.IPL10, false)
	addMap("ISC", expression.ISC, false)
	addMap("ISCL", expression.ISC, false)
	addMap("JQUERY", expression.MIT, false)
	addMap("LGPL-2", expression.LGPL20, false)
	addMap("LGPL-2.0", expression.LGPL20, false)
	addMap("LGPL-2.1", expression.LGPL21, false)
	addMap("LGPL-3", expression.LGPL30, false)
	addMap("LGPL-3.0", expression.LGPL30, false)
	addMap("LGPLLR", expression.LGPLLR, false)
	addMap("LIBPNG", expression.Libpng, false)
	addMap("LIL-1.0", expression.Lil10, false)
	addMap("LINUX-OPENIB", expression.LinuxOpenIB, false)
	addMap("LPL-1.0", expression.LPL10, false)
	addMap("LPL-1.02", expression.LPL102, false)
	addMap("LPPL-1.3C", expression.LPPL13c, false)
	addMap("MIT", expression.MIT, false)
	// MIT No Attribution (MIT-0) is not yet supported by google/licenseclassifier
	addMap("MIT-0", expression.MIT, false)
	addMap("MIT-LIKE", expression.MIT, false)
	addMap("MIT-STYLE", expression.MIT, false)
	addMap("MPL-1", expression.MPL10, false)
	addMap("MPL-1.0", expression.MPL10, false)
	addMap("MPL-1.1", expression.MPL11, false)
	addMap("MPL-2", expression.MPL20, false)
	addMap("MPL-2.0", expression.MPL20, false)
	addMap("MS-PL", expression.MSPL, false)
	addMap("NCSA", expression.NCSA, false)
	addMap("NPL-1.0", expression.NPL10, false)
	addMap("NPL-1.1", expression.NPL11, false)
	addMap("OFL-1.1", expression.OFL11, false)
	addMap("OPENSSL", expression.OpenSSL, false)
	addMap("OPENVISION", expression.OpenVision, false)
	addMap("OSL-1", expression.OSL10, false)
	addMap("OSL-1.0", expression.OSL10, false)
	addMap("OSL-1.1", expression.OSL11, false)
	addMap("OSL-2", expression.OSL20, false)
	addMap("OSL-2.0", expression.OSL20, false)
	addMap("OSL-2.1", expression.OSL21, false)
	addMap("OSL-3", expression.OSL30, false)
	addMap("OSL-3.0", expression.OSL30, false)
	addMap("PHP-3.0", expression.PHP30, false)
	addMap("PHP-3.01", expression.PHP301, false)
	addMap("PIL", expression.PIL, false)
	addMap("POSTGRESQL", expression.PostgreSQL, false)
	addMap("PYTHON-2", expression.Python20, false)
	addMap("PYTHON-2.0", expression.Python20, false)
	addMap("PYTHON-2.0-COMPLETE", expression.Python20complete, false)
	addMap("QPL-1", expression.QPL10, false)
	addMap("QPL-1.0", expression.QPL10, false)
	addMap("RUBY", expression.Ruby, false)
	addMap("SGI-B-1.0", expression.SGIB10, false)
	addMap("SGI-B-1.1", expression.SGIB11, false)
	addMap("SGI-B-2.0", expression.SGIB20, false)
	addMap("SISSL", expression.SISSL, false)
	addMap("SISSL-1.2", expression.SISSL12, false)
	addMap("SLEEPYCAT", expression.Sleepycat, false)
	addMap("UNICODE-DFS-2015", expression.UnicodeDFS2015, false)
	addMap("UNICODE-DFS-2016", expression.UnicodeDFS2016, false)
	addMap("UNICODE-TOU", expression.UnicodeTOU, false)
	addMap("UNLICENSE", expression.Unlicense, false)
	addMap("UNLICENSED", expression.Unlicense, false)
	addMap("UPL-1", expression.UPL10, false)
	addMap("UPL-1.0", expression.UPL10, false)
	addMap("W3C", expression.W3C, false)
	addMap("W3C-19980720", expression.W3C19980720, false)
	addMap("W3C-20150513", expression.W3C20150513, false)
	addMap("W3CL", expression.W3C, false)
	addMap("WTF", expression.WTFPL, false)
	addMap("WTFPL", expression.WTFPL, false)
	addMap("X11", expression.X11, false)
	addMap("XNET", expression.Xnet, false)
	addMap("ZEND-2", expression.Zend20, false)
	addMap("ZEND-2.0", expression.Zend20, false)
	addMap("ZLIB", expression.Zlib, false)
	addMap("ZLIB-ACKNOWLEDGEMENT", expression.ZlibAcknowledgement, false)
	addMap("ZOPE-1.1", expression.ZPL11, false)
	addMap("ZOPE-2.0", expression.ZPL20, false)
	addMap("ZOPE-2.1", expression.ZPL21, false)
	addMap("ZPL-1.1", expression.ZPL11, false)
	addMap("ZPL-2.0", expression.ZPL20, false)
	addMap("ZPL-2.1", expression.ZPL21, false)

	// Non simple declared mappings
	// modified from https://github.com/oss-review-toolkit/ort/blob/fc5389c2cfd9c8b009794c8a11f5c91321b7a730/utils/spdx/src/main/resources/declared-license-mapping.yml

	// Ambiguous declared mappings (mapping reason not obvious without additional information)
	addMap("ACADEMIC FREE LICENSE (AFL)", expression.AFL21, false)
	addMap("APACHE SOFTWARE LICENSES", expression.Apache20, false)
	addMap("APACHE SOFTWARE", expression.Apache20, false)
	addMap("APPLE PUBLIC SOURCE", expression.APSL10, false)
	addMap("BSD SOFTWARE", expression.BSD2Clause, false)
	addMap("BSD STYLE", expression.BSD3Clause, false)
	addMap("COMMON DEVELOPMENT AND DISTRIBUTION", expression.CDDL10, false)
	addMap("CREATIVE COMMONS - BY", expression.CCBY30, false)
	addMap("CREATIVE COMMONS ATTRIBUTION", expression.CCBY30, false)
	addMap("CREATIVE COMMONS", expression.CCBY30, false)
	addMap("ECLIPSE PUBLIC LICENSE (EPL)", expression.EPL10, false)
	addMap("GENERAL PUBLIC LICENSE (GPL)", expression.GPL20, true)
	addMap("GNU FREE DOCUMENTATION LICENSE (FDL)", expression.GFDL13, true)
	addMap("GNU GENERAL PUBLIC LIBRARY", expression.GPL30, true)
	addMap("GNU GENERAL PUBLIC LICENSE (GPL)", expression.GPL30, true)
	addMap("GNU GPL", expression.GPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC", expression.LGPL21, false)
	addMap("GNU LESSER PUBLIC", expression.LGPL21, false)
	addMap("GNU LESSER", expression.LGPL21, false)
	addMap("GNU LGPL", expression.LGPL21, false)
	addMap("GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE (LGPL)", expression.LGPL21, false)
	addMap("GNU PUBLIC", expression.GPL20, true)
	addMap("GPL (WITH DUAL LICENSING OPTION)", expression.GPL20, false)
	addMap("GPLV2 WITH EXCEPTIONS", expression.GPL20withclasspathexception, false)
	addMap("INDIVIDUAL BSD", expression.BSD3Clause, false)
	addMap("LESSER GENERAL PUBLIC LICENSE (LGPL)", expression.LGPL21, true)
	addMap("LGPL WITH EXCEPTIONS", expression.LGPL30, false)
	addMap("LPGL, SEE LICENSE FILE.", expression.LGPL30, true)
	addMap("MOZILLA PUBLIC", expression.MPL20, false)
	addMap("ZOPE PUBLIC", expression.ZPL21, false)

	// Non-ambiguous declared mappings
	addMap("(NEW) BSD", expression.BSD3Clause, false)
	addMap("2-CLAUSE BSD", expression.BSD2Clause, false)
	addMap("2-CLAUSE BSDL", expression.BSD2Clause, false)
	addMap("3-CLAUSE BDSL", expression.BSD3Clause, false)
	addMap("3-CLAUSE BSD", expression.BSD3Clause, false)
	addMap("ACADEMIC FREE LICENSE (AFL-2.1", expression.AFL21, false)
	addMap("AFFERO GENERAL PUBLIC LICENSE (AGPL-3", expression.AGPL30, false)
	addMap("APACHE 2 STYLE", expression.Apache20, false)
	addMap("APACHE LICENSE, ASL-2.0", expression.Apache20, false)
	addMap("APACHE LICENSE, VERSION 2.0 (HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0", expression.Apache20, false)
	addMap("APACHE PUBLIC-1.1", expression.Apache11, false)
	addMap("APACHE PUBLIC-2", expression.Apache20, false)
	addMap("APACHE PUBLIC-2.0", expression.Apache20, false)
	addMap("APACHE SOFTWARE LICENSE (APACHE-2", expression.Apache20, false)
	addMap("APACHE SOFTWARE LICENSE (APACHE-2.0", expression.Apache20, false)
	addMap("APACHE SOFTWARE-1.1", expression.Apache11, false)
	addMap("APACHE SOFTWARE-2", expression.Apache20, false)
	addMap("APACHE SOFTWARE-2.0", expression.Apache20, false)
	addMap("APACHE VERSION 2.0, JANUARY 2004", expression.Apache20, false)
	addMap("APACHE-2.0 */ &#39; &QUOT; &#X3D;END --", expression.Apache20, false)
	addMap("BERKELEY SOFTWARE DISTRIBUTION (BSD)", expression.BSD2Clause, false)
	addMap("BOOST SOFTWARE LICENSE 1.0 (BSL-1.0", expression.BSL10, false)
	addMap("BOOST SOFTWARE", expression.BSL10, false)
	addMap("BOUNCY CASTLE", expression.MIT, false)
	addMap("BSD (3-CLAUSE)", expression.BSD3Clause, false)
	addMap("BSD - SEE NDG/HTTPSCLIENT/LICENSE FILE FOR DETAILS", expression.BSD3Clause, false)
	addMap("BSD 2 CLAUSE", expression.BSD2Clause, false)
	addMap("BSD 2-CLAUSE", expression.BSD2Clause, false)
	addMap("BSD 3 CLAUSE", expression.BSD3Clause, false)
	addMap("BSD 3-CLAUSE NEW", expression.BSD3Clause, false)
	addMap("BSD 3-CLAUSE \"NEW\" OR \"REVISED\" LICENSE (BSD-3-CLAUSE)", expression.BSD3Clause, false)
	addMap("BSD 3-CLAUSE", expression.BSD3Clause, false)
	addMap("BSD 4 CLAUSE", expression.BSD4Clause, false)
	addMap("BSD 4-CLAUSE", expression.BSD4Clause, false)
	addMap("BSD FOUR CLAUSE", expression.BSD4Clause, false)
	addMap("BSD LICENSE FOR HSQL", expression.BSD3Clause, false)
	addMap("BSD NEW", expression.BSD3Clause, false)
	addMap("BSD THREE CLAUSE", expression.BSD3Clause, false)
	addMap("BSD TWO CLAUSE", expression.BSD2Clause, false)
	addMap("BSD-3 CLAUSE", expression.BSD3Clause, false)
	addMap("BSD-STYLE + ATTRIBUTION", expression.BSD3ClauseAttribution, false)
	addMap("CC BY-NC-SA-2.0", expression.CCBYNCSA20, false)
	addMap("CC BY-NC-SA-2.5", expression.CCBYNCSA25, false)
	addMap("CC BY-NC-SA-3.0", expression.CCBYNCSA30, false)
	addMap("CC BY-NC-SA-4.0", expression.CCBYNCSA40, false)
	addMap("CC BY-SA-2.0", expression.CCBYSA20, false)
	addMap("CC BY-SA-2.5", expression.CCBYSA25, false)
	addMap("CC BY-SA-3.0", expression.CCBYSA30, false)
	addMap("CC BY-SA-4.0", expression.CCBYSA40, false)
	addMap("CC0 1.0 UNIVERSAL (CC0 1.0) PUBLIC DOMAIN DEDICATION", expression.CC010, false)
	addMap("CC0 1.0 UNIVERSAL", expression.CC010, false)
	addMap("COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)-1.0", expression.CDDL10, false)
	addMap("COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL)-1.1", expression.CDDL11, false)
	addMap("COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.0 (CDDL-1.0", expression.CDDL10, false)
	addMap("COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.1 (CDDL-1.1", expression.CDDL11, false)
	addMap("COMMON PUBLIC", expression.CPL10, false)
	addMap("COMMON PUBLIC-1.0", expression.CPL10, false)
	addMap("CREATIVE COMMONS - ATTRIBUTION 4.0 INTERNATIONAL", expression.CCBY40, false)
	addMap("CREATIVE COMMONS 3.0 BY-SA", expression.CCBYSA30, false)
	addMap("CREATIVE COMMONS ATTRIBUTION 3.0 UNPORTED (CC BY-3.0", expression.CCBY30, false)
	addMap("CREATIVE COMMONS ATTRIBUTION 4.0 INTERNATIONAL (CC BY-4.0", expression.CCBY40, false)
	addMap("CREATIVE COMMONS ATTRIBUTION 4.0 INTERNATIONAL PUBLIC", expression.CCBY40, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-1.0", expression.CCBY10, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-2.5", expression.CCBY25, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-3.0", expression.CCBY30, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-4.0", expression.CCBY40, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL 4.0 INTERNATIONAL", expression.CCBYNC40, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-NODERIVATIVES 4.0 INTERNATIONAL", expression.CCBYNCND40, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 3.0 UNPORTED (CC BY-NC-SA-3.0", expression.CCBYNCSA30, false)
	addMap("CREATIVE COMMONS ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 4.0 INTERNATIONAL PUBLIC", expression.CCBYNCSA40, false)
	addMap("CREATIVE COMMONS CC0", expression.CC010, false)
	addMap("CREATIVE COMMONS GNU LGPL-2.1", expression.LGPL21, false)
	addMap("CREATIVE COMMONS LICENSE ATTRIBUTION-NODERIVS 3.0 UNPORTED", expression.CCBYNCND30, false)
	addMap("CREATIVE COMMONS LICENSE ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 3.0 UNPORTED", expression.CCBYNCSA30, false)
	addMap("CREATIVE COMMONS ZERO", expression.CC010, false)
	addMap("CREATIVE COMMONS-3.0", expression.CCBY30, false)
	addMap("ECLIPSE DISTRIBUTION LICENSE (EDL)-1.0", expression.BSD3Clause, false)
	addMap("ECLIPSE DISTRIBUTION LICENSE (NEW BSD LICENSE)", expression.BSD3Clause, false)
	addMap("ECLIPSE DISTRIBUTION-1.0", expression.BSD3Clause, false)
	addMap("ECLIPSE PUBLIC LICENSE (EPL)-1.0", expression.EPL10, false)
	addMap("ECLIPSE PUBLIC LICENSE (EPL)-2.0", expression.EPL20, false)
	addMap("ECLIPSE PUBLIC LICENSE 1.0 (EPL-1.0", expression.EPL10, false)
	addMap("ECLIPSE PUBLIC LICENSE 2.0 (EPL-2.0", expression.EPL20, false)
	addMap("ECLIPSE PUBLIC", expression.EPL10, false)
	addMap("ECLIPSE PUBLIC-1.0", expression.EPL10, false)
	addMap("ECLIPSE PUBLIC-2.0", expression.EPL20, false)
	addMap("ECLIPSE PUBLISH-1.0", expression.EPL10, false)
	addMap("EPL (ECLIPSE PUBLIC LICENSE)-1.0", expression.EPL10, false)
	addMap("EU PUBLIC LICENSE 1.0 (EUPL-1.0", expression.EUPL10, false)
	addMap("EU PUBLIC LICENSE 1.1 (EUPL-1.1", expression.EUPL11, false)
	addMap("EUROPEAN UNION PUBLIC LICENSE (EUPL-1.0", expression.EUPL10, false)
	addMap("EUROPEAN UNION PUBLIC LICENSE (EUPL-1.1", expression.EUPL11, false)
	addMap("EUROPEAN UNION PUBLIC LICENSE 1.0 (EUPL-1.0", expression.EUPL10, false)
	addMap("EUROPEAN UNION PUBLIC LICENSE 1.1 (EUPL-1.1", expression.EUPL11, false)
	addMap("EUROPEAN UNION PUBLIC-1.0", expression.EUPL10, false)
	addMap("EUROPEAN UNION PUBLIC-1.1", expression.EUPL11, false)
	addMap("EXPAT (MIT/X11)", expression.MIT, false)
	addMap("GENERAL PUBLIC LICENSE 2.0 (GPL)", expression.GPL20, false)
	addMap("GNU AFFERO GENERAL PUBLIC LICENSE V3 (AGPL-3", expression.AGPL30, false)
	addMap("GNU AFFERO GENERAL PUBLIC LICENSE V3 (AGPL-3.0", expression.AGPL30, false)
	addMap("GNU AFFERO GENERAL PUBLIC LICENSE V3 OR LATER (AGPL3+)", expression.AGPL30, true)
	addMap("GNU AFFERO GENERAL PUBLIC LICENSE V3 OR LATER (AGPLV3+)", expression.AGPL30, true)
	addMap("GNU AFFERO GENERAL PUBLIC-3", expression.AGPL30, false)
	addMap("GNU FREE DOCUMENTATION LICENSE (GFDL-1.3", expression.GFDL13, false)
	addMap("GNU GENERAL LESSER PUBLIC LICENSE (LGPL)-2.1", expression.LGPL21, false)
	addMap("GNU GENERAL LESSER PUBLIC LICENSE (LGPL)-3.0", expression.LGPL30, false)
	addMap("GNU GENERAL PUBLIC LICENSE (GPL), VERSION 2, WITH CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE (GPL), VERSION 2, WITH THE CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE (GPL)-2", expression.GPL20, false)
	addMap("GNU GENERAL PUBLIC LICENSE (GPL)-3", expression.GPL30, false)
	addMap("GNU GENERAL PUBLIC LICENSE V2 (GPL-2", expression.GPL20, false)
	addMap("GNU GENERAL PUBLIC LICENSE V2 OR LATER (GPLV2+)", expression.GPL20, true)
	addMap("GNU GENERAL PUBLIC LICENSE V2.0 ONLY, WITH CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE V3 (GPL-3", expression.GPL30, false)
	addMap("GNU GENERAL PUBLIC LICENSE V3 OR LATER (GPLV3+)", expression.GPL30, true)
	addMap("GNU GENERAL PUBLIC LICENSE VERSION 2 (GPL-2", expression.GPL20, false)
	addMap("GNU GENERAL PUBLIC LICENSE VERSION 2, JUNE 1991", expression.GPL20, false)
	addMap("GNU GENERAL PUBLIC LICENSE VERSION 3 (GPL-3", expression.GPL30, false)
	addMap("GNU GENERAL PUBLIC LICENSE, VERSION 2 (GPL2), WITH THE CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE, VERSION 2 WITH THE CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE, VERSION 2 WITH THE GNU CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC LICENSE, VERSION 2, WITH THE CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GNU GENERAL PUBLIC-2", expression.GPL20, false)
	addMap("GNU GENERAL PUBLIC-3", expression.GPL30, false)
	addMap("GNU GPL-2", expression.GPL20, false)
	addMap("GNU GPL-3", expression.GPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2.0", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-2.1", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-3", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL)-3.0", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2.0", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL-2.1", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL-3", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE (LGPL-3.0", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE V2 (LGPL-2", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE V2 OR LATER (LGPLV2+)", expression.LGPL20, true)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE V3 (LGPL-3", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE V3 OR LATER (LGPLV3+)", expression.LGPL30, true)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE VERSION 2.1 (LGPL-2.1", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE VERSION 2.1, FEBRUARY 1999", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC LICENSE, VERSION 2.1, FEBRUARY 1999", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC-2", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC-2.0", expression.LGPL20, false)
	addMap("GNU LESSER GENERAL PUBLIC-2.1", expression.LGPL21, false)
	addMap("GNU LESSER GENERAL PUBLIC-3", expression.LGPL30, false)
	addMap("GNU LESSER GENERAL PUBLIC-3.0", expression.LGPL30, false)
	addMap("GNU LGP (GNU GENERAL PUBLIC LICENSE)-2", expression.LGPL20, false)
	addMap("GNU LGPL (GNU LESSER GENERAL PUBLIC LICENSE)-2.1", expression.LGPL21, false)
	addMap("GNU LGPL-2", expression.LGPL20, false)
	addMap("GNU LGPL-2.0", expression.LGPL20, false)
	addMap("GNU LGPL-2.1", expression.LGPL21, false)
	addMap("GNU LGPL-3", expression.LGPL30, false)
	addMap("GNU LGPL-3.0", expression.LGPL30, false)
	addMap("GNU LIBRARY GENERAL PUBLIC-2.0", expression.LGPL20, false)
	addMap("GNU LIBRARY GENERAL PUBLIC-2.1", expression.LGPL21, false)
	addMap("GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 2.0 (LGPL-2", expression.LGPL20, false)
	addMap("GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 3.0 (LGPL-3", expression.LGPL30, false)
	addMap("GPL (≥ 3)", expression.GPL30, true)
	addMap("GPL 2 WITH CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GPL V2 WITH CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GPL-2+ WITH AUTOCONF EXCEPTION", expression.GPL20withautoconfexception, true)
	addMap("GPL-3+ WITH AUTOCONF EXCEPTION", expression.GPL30withautoconfexception, true)
	addMap("GPL2 W/ CPE", expression.GPL20withclasspathexception, false)
	addMap("GPLV2 LICENSE, INCLUDES THE CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("GPLV2 WITH CLASSPATH EXCEPTION", expression.GPL20withclasspathexception, false)
	addMap("HSQLDB LICENSE, A BSD OPEN SOURCE", expression.BSD3Clause, false)
	addMap("HTTP://ANT-CONTRIB.SOURCEFORGE.NET/TASKS/LICENSE.TXT", expression.Apache11, false)
	addMap("HTTP://ASM.OW2.ORG/LICENSE.HTML", expression.BSD3Clause, false)
	addMap("HTTP://CREATIVECOMMONS.ORG/PUBLICDOMAIN/ZERO/1.0/LEGALCODE", expression.CC010, false)
	addMap("HTTP://EN.WIKIPEDIA.ORG/WIKI/ZLIB_LICENSE", expression.Zlib, false)
	addMap("HTTP://JSON.CODEPLEX.COM/LICENSE", expression.MIT, false)
	addMap("HTTP://POLYMER.GITHUB.IO/LICENSE.TXT", expression.BSD3Clause, false)
	addMap("HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0", expression.Apache20, false)
	addMap("HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0.HTML", expression.Apache20, false)
	addMap("HTTP://WWW.APACHE.ORG/LICENSES/LICENSE-2.0.TXT", expression.Apache20, false)
	addMap("HTTP://WWW.GNU.ORG/COPYLEFT/LESSER.HTML", expression.LGPL30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/1.0", expression.CCBYNCND10, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/2.0", expression.CCBYNCND20, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/2.5", expression.CCBYNCND25, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/3.0", expression.CCBYNCND30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-ND/4.0", expression.CCBYNCND40, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/1.0", expression.CCBYNCSA10, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/2.0", expression.CCBYNCSA20, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/2.5", expression.CCBYNCSA25, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/3.0", expression.CCBYNCSA30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-NC-SA/4.0", expression.CCBYNCSA40, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/1.0", expression.CCBYND10, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/2.0", expression.CCBYND20, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/2.5", expression.CCBYND25, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/3.0", expression.CCBYND30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-ND/4.0", expression.CCBYND40, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/1.0", expression.CCBYSA10, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/2.0", expression.CCBYSA20, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/2.5", expression.CCBYSA25, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/3.0", expression.CCBYSA30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY-SA/4.0", expression.CCBYSA40, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/1.0", expression.CCBY10, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/2.0", expression.CCBY20, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/2.5", expression.CCBY25, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/3.0", expression.CCBY30, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/LICENSES/BY/4.0", expression.CCBY40, false)
	addMap("HTTPS://CREATIVECOMMONS.ORG/PUBLICDOMAIN/ZERO/1.0/", expression.CC010, false)
	addMap("HTTPS://GITHUB.COM/DOTNET/CORE-SETUP/BLOB/MASTER/LICENSE.TXT", expression.MIT, false)
	addMap("HTTPS://GITHUB.COM/DOTNET/COREFX/BLOB/MASTER/LICENSE.TXT", expression.MIT, false)
	addMap("HTTPS://RAW.GITHUB.COM/RDFLIB/RDFLIB/MASTER/LICENSE", expression.BSD3Clause, false)
	addMap("HTTPS://RAW.GITHUBUSERCONTENT.COM/ASPNET/ASPNETCORE/2.0.0/LICENSE.TXT", expression.Apache20, false)
	addMap("HTTPS://RAW.GITHUBUSERCONTENT.COM/ASPNET/HOME/2.0.0/LICENSE.TXT", expression.Apache20, false)
	addMap("HTTPS://RAW.GITHUBUSERCONTENT.COM/NUGET/NUGET.CLIENT/DEV/LICENSE.TXT", expression.Apache20, false)
	addMap("HTTPS://WWW.APACHE.ORG/LICENSES/LICENSE-2.0", expression.Apache20, false)
	addMap("HTTPS://WWW.ECLIPSE.ORG/LEGAL/EPL-V10.HTML", expression.EPL10, false)
	addMap("HTTPS://WWW.ECLIPSE.ORG/LEGAL/EPL-V20.HTML", expression.EPL20, false)
	addMap("IBM PUBLIC", expression.IPL10, false)
	addMap("ISC LICENSE (ISCL)", expression.ISC, false)
	addMap("JYTHON SOFTWARE", expression.Python20, false)
	addMap("KIRKK.COM BSD", expression.BSD3Clause, false)
	addMap("LESSER GENERAL PUBLIC LICENSE, VERSION 3 OR GREATER", expression.LGPL30, true)
	addMap("LICENSE AGREEMENT FOR OPEN SOURCE COMPUTER VISION LIBRARY (3-CLAUSE BSD LICENSE)", expression.BSD3Clause, false)
	addMap("MIT (HTTP://MOOTOOLS.NET/LICENSE.TXT)", expression.MIT, false)
	addMap("MIT / HTTP://REM.MIT-LICENSE.ORG", expression.MIT, false)
	addMap("MIT LICENSE (HTTP://OPENSOURCE.ORG/LICENSES/MIT)", expression.MIT, false)
	addMap("MIT LICENSE (MIT)", expression.MIT, false)
	addMap("MIT LICENSE(MIT)", expression.MIT, false)
	addMap("MIT LICENSED. HTTP://WWW.OPENSOURCE.ORG/LICENSES/MIT-LICENSE.PHP", expression.MIT, false)
	addMap("MIT/EXPAT", expression.MIT, false)
	addMap("MOCKRUNNER LICENSE, BASED ON APACHE SOFTWARE-1.1", expression.Apache11, false)
	addMap("MODIFIED BSD", expression.BSD3Clause, false)
	addMap("MOZILLA PUBLIC LICENSE 1.0 (MPL)", expression.MPL10, false)
	addMap("MOZILLA PUBLIC LICENSE 1.1 (MPL-1.1", expression.MPL11, false)
	addMap("MOZILLA PUBLIC LICENSE 2.0 (MPL-2.0", expression.MPL20, false)
	addMap("MOZILLA PUBLIC-1.0", expression.MPL10, false)
	addMap("MOZILLA PUBLIC-1.1", expression.MPL11, false)
	addMap("MOZILLA PUBLIC-2.0", expression.MPL20, false)
	addMap("NCSA OPEN SOURCE", expression.NCSA, false)
	addMap("NETSCAPE PUBLIC LICENSE (NPL)", expression.NPL10, false)
	addMap("NETSCAPE PUBLIC", expression.NPL10, false)
	addMap("NEW BSD", expression.BSD3Clause, false)
	addMap("OPEN SOFTWARE LICENSE 3.0 (OSL-3.0", expression.OSL30, false)
	addMap("OPEN SOFTWARE-3.0", expression.OSL30, false)
	addMap("PERL ARTISTIC-2", expression.Artistic10Perl, false)
	// Note: public domain without a specific license should not be mapped
	// see https://wiki.spdx.org/view/Legal_Team/Decisions/Dealing_with_Public_Domain_within_SPDX_Files
	// and https://opensource.google/documentation/reference/thirdparty/licenses#unencumbered
	addMap("PUBLIC DOMAIN (CC0-1.0)", expression.CC010, false)
	addMap("PUBLIC DOMAIN, PER CREATIVE COMMONS CC0", expression.CC010, false)
	addMap("QT PUBLIC LICENSE (QPL)", expression.QPL10, false)
	addMap("QT PUBLIC", expression.QPL10, false)
	addMap("REVISED BSD", expression.BSD3Clause, false)
	addMap("RUBY'S", expression.Ruby, false)
	addMap("SEQUENCE LIBRARY LICENSE (BSD-LIKE)", expression.BSD3Clause, false)
	addMap("SIL OPEN FONT LICENSE 1.1 (OFL-1.1", expression.OFL11, false)
	addMap("SIL OPEN FONT-1.1", expression.OFL11, false)
	addMap("SIMPLIFIED BSD LISCENCE", expression.BSD2Clause, false)
	addMap("SIMPLIFIED BSD", expression.BSD2Clause, false)
	addMap("SUN INDUSTRY STANDARDS SOURCE LICENSE (SISSL)", expression.SISSL, false)
	addMap("THREE-CLAUSE BSD-STYLE", expression.BSD3Clause, false)
	addMap("TWO-CLAUSE BSD-STYLE", expression.BSD2Clause, false)
	addMap("UNIVERSAL PERMISSIVE LICENSE (UPL)", expression.UPL10, false)
	addMap("UNIVERSAL PERMISSIVE-1.0", expression.UPL10, false)
	addMap("UNLICENSE (UNLICENSE)", expression.Unlicense, false)
	addMap("W3C SOFTWARE", expression.W3C, false)
	addMap("ZLIB / LIBPNG", expression.ZlibAcknowledgement, false)
	addMap("ZLIB/LIBPNG", expression.ZlibAcknowledgement, false)

	addMap("['MIT']", expression.MIT, false)
}

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

// version number match
var versionRegexpString = "([A-UW-Z)]{2,})( LICENSE)?\\s*[,(-]?\\s*(V|V\\.|VERSION|VERSION-|-)?\\s*([1-9](\\.\\d)*)[)]?"

// case insensitive version match anywhere in string
var versionRegexp = regexp.MustCompile("(?i)" + versionRegexpString)

// version suffix match
var versionSuffixRegexp = regexp.MustCompile(versionRegexpString + "$")

// suffixes from https://spdx.dev/learn/handling-license-info/
var onlySuffixes = [2]string{"-ONLY", " ONLY"}
var plusSuffixes = [3]string{"+", "-OR-LATER", " OR LATER"}

func standardizeKeyAndSuffix(name string) expression.SimpleExpr {
	// Standardize space, including newline
	name = strings.Join(strings.Fields(name), " ")
	name = strings.TrimSpace(name)
	name = strings.ToUpper(name)
	// Do not perform any further normalization for URLs
	if strings.HasPrefix(name, "HTTP") {
		return expression.SimpleExpr{License: name, HasPlus: false}
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
	return expression.SimpleExpr{License: name, HasPlus: hasPlus}
}

// Returns invalid keys in a map between license strings and normalized licenses.
// The map keys must be standardized (uppercase, no common suffixes, etc.).
// A nil argument will return invalid keys in the default mapping.
func InvalidMappingKeys(licenseToNormalized map[string]expression.SimpleExpr) []string {
	if licenseToNormalized == nil {
		licenseToNormalized = mapping
	}
	var invalid []string
	for key := range licenseToNormalized {
		standardized := standardizeKeyAndSuffix(key)
		if standardized.License != key {
			invalid = append(invalid, key)
		}
	}
	return invalid
}

func Normalize(name string) string {
	return NormalizeLicense(name).String()
}

func NormalizeLicense(name string) expression.SimpleExpr {
	normalized := standardizeKeyAndSuffix(name)
	if found, ok := mapping[normalized.License]; ok {
		return expression.SimpleExpr{License: found.License, HasPlus: found.HasPlus || normalized.HasPlus}
	}
	return expression.SimpleExpr{License: name, HasPlus: false}
}

func SplitLicenses(str string) []string {
	if str == "" {
		return nil
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
