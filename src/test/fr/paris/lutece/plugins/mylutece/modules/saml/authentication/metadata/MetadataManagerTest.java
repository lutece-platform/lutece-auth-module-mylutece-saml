package fr.paris.lutece.plugins.mylutece.modules.saml.authentication.metadata;

import junit.framework.TestCase;

import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;

public class MetadataManagerTest extends TestCase {

	@Override
	protected void setUp() throws Exception {
		// Initialize the OpenSAML library
		DefaultBootstrap.bootstrap();
	}

	public void testMetadataManager() {
		
		// Chargement fichier de test
		IDPMetadataManager idpManager = new IDPMetadataManager();	
		idpManager.loadMetadata("/resources/data/valid-idp-metadata.xml");
		
		EntityDescriptor idpMetadata = idpManager.getMetaData();

		String entityID = "urn:fi:dictao:shib:1.0";
		assertEquals("Test IDP Metadata EntityID : " + idpMetadata.getEntityID() + ", expected a value of "
                + entityID, entityID, idpMetadata.getEntityID());
	}

}
