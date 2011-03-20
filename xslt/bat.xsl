<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet 
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns="http://www.w3.org/1999/xhtml">
       
<xsl:output method="xml" indent="yes" encoding="UTF-8"/>

<xsl:template match="/report">
<html>
    <head>
        <title>BAT analysis report</title>
    </head>
    <body>
        <h1>Report</h1>
        <ul>
         <li>Scandate: <xsl:value-of select="scandate" /></li>
         <li>Filename: <xsl:value-of select="name" /></li>
         <li><xsl:apply-templates select="scans" /></li>
        </ul>
    </body>
</html>
</xsl:template>
                                                                                       
<xsl:template match="scans">
      <ul>
      <xsl:apply-templates match="unpack" />
      </ul>
</xsl:template>

<xsl:template match="unpack">
      <li>type: <xsl:value-of select="type"/></li>
      <li>offset in parent file: <xsl:value-of select="offset"/></li>
      <li><xsl:apply-templates select="file" /></li>
</xsl:template>
                         
<xsl:template match="file">
      <ul>
      <li>Name: <xsl:value-of select="name"/></li>
      <li>magic: <xsl:value-of select="magic"/></li>
      <li><xsl:apply-templates select="scans" /></li>
      </ul>
</xsl:template>

</xsl:stylesheet>
