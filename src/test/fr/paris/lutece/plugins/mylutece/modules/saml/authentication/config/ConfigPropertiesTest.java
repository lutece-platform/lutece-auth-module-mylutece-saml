package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.config;

import junit.framework.TestCase;

public class ConfigPropertiesTest extends TestCase {

	public void testConfigProperties() {
		try {
			ConfigProperties.getInstance().setTest(true);
			ConfigProperties.init();
		} catch (Exception e) {	
			fail("ConfigProperties.init() failed");
		}
		
		ConfigProperties instance = ConfigProperties.getInstance();
		assertNotNull("ConfigProperties instance is null", instance);
		
		assertNotNull(instance.getProperty(Constants.IDP_METADATA_FILE_PROP));
		assertNotNull(instance.getProperty(Constants.SP_METADATA_FILE_PROP));
	}
}
