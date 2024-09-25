package azure

import (
	"github.com/infracost/infracost/internal/resources/azure"
	"github.com/infracost/infracost/internal/schema"
)

func getAppServiceCertificateOrderRegistryItem() *schema.RegistryItem {
	return &schema.RegistryItem{
		Name:      "Microsoft.CertificateRegistration/certificateOrders",
		CoreRFunc: NewAppServiceCertificateOrder,
	}
}
func NewAppServiceCertificateOrder(d *schema.ResourceData) schema.CoreResource {
	r := &azure.AppServiceCertificateOrder{Address: d.Address, ProductType: getProductType(d.Get("properties.productType").String())}
	return r
}

func getProductType(productType string) string {
	if productType == "StandardDomainValidatedSsl" {
		return ""
	} else if productType == "WildcardDomainValidatedSsl" {
		return "WildCard"
	}
	return productType
}
