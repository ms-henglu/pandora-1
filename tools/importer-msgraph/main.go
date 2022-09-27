package main

import (
	"fmt"
	"github.com/getkin/kin-openapi/openapi3"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	spec, err := load("openapi-v1.0.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = parse(spec)
	if err != nil {
		log.Fatal(err)
	}

}

func load(filename string) (*openapi3.T, error) {
	//yamlData, err := os.ReadFile(filename)
	//if err != nil {
	//	return nil, err
	//}
	//jsonData, err := yaml.YAMLToJSON(yamlData)
	//if err != nil {
	//	return nil, err
	//}
	//spec, err := loads.Analyzed(jsonData, "")
	//if err != nil {
	//	return nil, err
	//}
	spec, err := openapi3.NewLoader().LoadFromFile(filename)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

func parse(spec *openapi3.T) error {
	tags := make([]string, 0)
	for _, tag := range spec.Tags {
		if tag == nil {
			continue
		}
		if tag.Name != "" {
			tags = append(tags, tag.Name)
		}
	}

	endpoints := parseEndpoints(spec.Paths)

	// smaller map for easier inspection
	//applications := make([]*Endpoint, 0)
	//for _, endpoint := range endpoints {
	//	if strings.Contains(endpoint., "application") {
	//		applications[tag] = endpoint
	//	}
	//}

	colls := make([]*Endpoint, 0)
	for _, e := range endpoints {
		for _, o := range e.Operations {
			for _, r := range o.Responses {
				if r.Collection {
					colls = append(colls, e)
				}
			}
		}
	}

	fmt.Println("%T", endpoints)

	models := parseModelSchemas(spec.Components.Schemas)

	if err := writeModels(models); err != nil {
		return err
	}

	//appSchemas := make(openapi3.Schemas)
	//for k, v := range spec.Components.Schemas {
	//	if strings.HasPrefix(k, "microsoft.graph.application") {
	//		appSchemas[k] = v
	//	}
	//}
	//fmt.Printf("%T", appSchemas)
	//
	//appModels := make(map[string]*Model, 0)
	//for n, m := range models {
	//	if strings.HasPrefix(n, "Application") {
	//		appModels[n] = m
	//	}
	//}
	//fmt.Printf("%T", appModels)

	return nil
}

func writeModels(models Models) error {
	tmpl := make([]string, 0)
	seenums := make(map[string]uint8, 0)
	for name, model := range models {
		fields := make([]string, 0)
		for n, f := range model.Fields {
			//if n[:1] == "@" {
			//	continue
			//}
			fields = append(fields, fmt.Sprintf(`	%s %s %s`, cleanName(n), f.GoType(), f.GoTag()))
			if _, seen := seenums[f.Title]; f.Type == FieldTypeString && f.Enum != nil && !seen {
				seenums[f.Title] = 1
				vals := make([]string, 0)
				for _, e := range f.Enum {
					vals = append(vals, fmt.Sprintf("%[1]s%[2]s %[1]s = %[3]q", f.Title, strings.Title(fmt.Sprintf("%s", e)), e))
				}
				tmpl = append(tmpl, fmt.Sprintf(`type %s string

const (
	%s
)`, f.Title, strings.Join(vals, "\n\t")))
			}
		}
		if len(fields) == 0 {
			continue
		}
		sort.Strings(fields)
		tmpl = append(tmpl, fmt.Sprintf(`type %s struct {
%s
}`, name, strings.Join(fields, "\n")))
	}
	sort.Strings(tmpl)
	tmpls := fmt.Sprintf("package output\n\nimport (\n\t\"time\"\n)\n\n%s\n\n%s", CustomTypes, strings.Join(tmpl, "\n\n"))
	outPath := "/Users/tom/git/hashicorp/pandora/tools/importer-msgraph/output/models.go"
	err := os.WriteFile(outPath, []byte(tmpls), 0644)
	if err != nil {
		return err
	}
	err = exec.Command("gofmt", "-w", outPath).Run()
	if err != nil {
		return err
	}
	return nil
}

type ResourceId struct {
	segments []ResourceIdSegment
}

type ResourceIdSegment struct {
	Type  ResourceIdSegmentType
	Value string
	Field *string
}

type ResourceIdSegmentType uint

const (
	SegmentApiVersion ResourceIdSegmentType = iota
	SegmentTenantId
	SegmentLabel
	SegmentAction
	SegmentUserValue
	SegmentCast
	SegmentFunction
)

const CustomTypes string = `
type UUID struct {}
`

func normalizeFieldName(segment string) (field string) {
	if segment[0] == '{' {
		field = segment[1 : len(segment)-1]
		field = strings.Title(field)
		field = regexp.MustCompile("([^A-Za-z0-9])").ReplaceAllString(field, "")
	}
	return
}

func NewResourceId(path string, tags []string) (id ResourceId) {
	tagSuffix := func(suffix string) bool {
		for _, t := range tags {
			if strings.HasSuffix(strings.ToLower(t), suffix) {
				return true
			}
		}
		return false
	}
	id.segments = []ResourceIdSegment{
		{SegmentApiVersion, "v1.0", nil},
		{SegmentTenantId, "{tenant-id}", nil},
	}

	segments := strings.FieldsFunc(path, func(c rune) bool { return c == '/' })
	for _, s := range segments {
		segment := ResourceIdSegment{}
		if field := normalizeFieldName(s); field != "" {
			segment = ResourceIdSegment{SegmentUserValue, s, &field}
		} else {
			if strings.HasPrefix(strings.ToLower(s), "microsoft.graph.") {
				if strings.Contains(s, "(") {
					segment = ResourceIdSegment{SegmentFunction, s, nil}
				} else if tagSuffix(".actions") {
					segment = ResourceIdSegment{SegmentAction, s, nil}
				} else {
					segment = ResourceIdSegment{SegmentCast, s, nil}
				}
			} else {
				segment = ResourceIdSegment{SegmentLabel, s, nil}
			}
		}
		id.segments = append(id.segments, segment)
	}
	return
}

type Endpoint struct {
	Id         ResourceId
	Operations []Operation
}

type Operation struct {
	Type         OperationType
	Method       string
	RequestModel interface{}
	Responses    []Response
	Tags         []string
}

type Response struct {
	Status      int
	ContentType *string
	Collection  bool
	ModelName   *string
}

type OperationType uint8

func NewOperationType(method string) OperationType {
	switch method {
	case http.MethodGet:
		return OperationTypeRead
	case http.MethodPost:
		return OperationTypeCreate
	case http.MethodPatch:
		return OperationTypeUpdate
	case http.MethodPut:
		return OperationTypeCreateUpdate
	case http.MethodDelete:
		return OperationTypeDelete
	}
	return OperationTypeUnknown
}

const (
	OperationTypeUnknown OperationType = iota
	OperationTypeList
	OperationTypeRead
	OperationTypeCreate
	OperationTypeCreateUpdate
	OperationTypeUpdate
	OperationTypeDelete
)

func parseEndpoints(paths openapi3.Paths) (ret []*Endpoint) {
	ret = make([]*Endpoint, 0)
	for path, item := range paths {
		endpoint := Endpoint{
			Id:         NewResourceId(path, make([]string, 0)),
			Operations: make([]Operation, 0),
			//Tags: operation.Tags,
		}
		for method, operation := range item.Operations() {
			responses := make([]Response, 0)
			if operation.Responses != nil {
				for stat, resp := range operation.Responses {
					var status int
					var contentType, model *string
					var collection bool
					// TODO: expand this
					if s, err := strconv.Atoi(strings.ReplaceAll(stat, "X", "0")); err == nil {
						status = s
					}
					if resp.Value != nil && resp.Value.Content != nil {
						for t, m := range resp.Value.Content {
							contentType = &t
							if s := parseSchemaRef(m.Schema); s != nil {
								f, _ := flattenSchema(s, nil)
								if f.title != "" {
									if strings.HasPrefix(f.title, "Collection of ") {
										f.title = f.title[14:]
										collection = true
									}
									model = &f.title
								}
							}
							break
						}
					}
					responses = append(responses, Response{
						Status:      status,
						ContentType: contentType,
						Collection:  collection,
						ModelName:   model,
					})
				}
			}
			endpoint.Operations = append(endpoint.Operations, Operation{
				Type:         NewOperationType(method),
				Method:       method,
				RequestModel: nil,
				Responses:    responses,
				Tags:         operation.Tags,
			})
		}
		ret = append(ret, &endpoint)
	}
	return
}

// Schemas is a map[string]*SchemaRef
// SchemaRef is a struct{Ref, Value} where Ref is a string, Value is a *Schema
// The Ref string (after trimming) indicates a Schemas map key to follow/inherit
// Schema has Properties which is a nested Schemas
// Schema has AllOf which is a SchemaRefs
// SchemaRefs is a []*SchemaRef

// Schemas is a model
// SchemaRefs, SchemaRef lead to a Schema or other another SchemaRef
// Schema leads to SchemaRefs and Schemas

type Models map[string]*Model

func (m Models) Found(modelName string) (ok bool) {
	_, ok = m[modelName]
	return
}

type Model struct {
	Fields map[string]*ModelField
}

func (m Model) Merge(m2 Model) {
}

type ModelField struct {
	Title       string
	Type        FieldType
	Description string
	Default     interface{}
	Enum        []interface{}
	ModelName   string
	JsonField   string
}

func (f ModelField) GoTag() string {
	return fmt.Sprintf("`json:\"%s,omitempty\"`", f.JsonField)
}

func (f ModelField) GoType() string {
	switch f.Type {
	case FieldTypeModel:
		if f.ModelName == "" {
			return "interface{}" // TODO: model not found
		}
		return fmt.Sprintf("*%s", f.ModelName)
	case FieldTypeArray:
		if f.ModelName == "" {
			return "[]interface{}" // TODO: model not found
		}
		return fmt.Sprintf("*[]%s", f.ModelName)
	case FieldTypeString:
		if f.Enum != nil {
			return fmt.Sprintf("*%s", f.Title)
		}
		return "*string"
	case FieldTypeInteger:
		return "*int"
	case FieldTypeIntegerUnsigned:
		return "*uint"
	case FieldTypeInteger32:
		return "*int32"
	case FieldTypeIntegerUnsigned32:
		return "*uint32"
	case FieldTypeInteger16:
		return "*int16"
	case FieldTypeIntegerUnsigned16:
		return "*uint16"
	case FieldTypeInteger8:
		return "*int8"
	case FieldTypeIntegerUnsigned8:
		return "*uint8"
	case FieldTypeBool:
		return "*bool"
	case FieldTypeInterface:
		return "interface{}"
	case FieldTypeBase64:
		return "[]byte"
	case FieldTypeDate:
		return "time.Time" // TODO: date
	case FieldTypeDateTime:
		return "time.Time"
	case FieldTypeDuration:
		return "*string" // TODO: ISO8601 duration
	case FieldTypeTime:
		return "time.Time" // TODO: time
	case FieldTypeUuid:
		return "*UUID"
	}
	return ""
}

type FieldType uint8

const (
	FieldTypeModel FieldType = iota
	FieldTypeArray
	FieldTypeString
	FieldTypeInteger
	FieldTypeIntegerUnsigned
	FieldTypeInteger32
	FieldTypeIntegerUnsigned32
	FieldTypeInteger16
	FieldTypeIntegerUnsigned16
	FieldTypeInteger8
	FieldTypeIntegerUnsigned8
	FieldTypeBool
	FieldTypeInterface
	FieldTypeBase64
	FieldTypeDate
	FieldTypeDateTime
	FieldTypeDuration
	FieldTypeTime
	FieldTypeUuid
)

func cleanName(name string) string {
	name = strings.Title(strings.TrimPrefix(name, "microsoft.graph."))
	name = regexp.MustCompile("[^a-zA-Z0-9]").ReplaceAllString(name, "")
	name = regexp.MustCompile("^Is([A-Z])").ReplaceAllString(name, "$1")
	name = regexp.MustCompile("^Odata").ReplaceAllString(name, "OData")
	name = regexp.MustCompile("^Innererror").ReplaceAllString(name, "InnerError")
	return name
}

func parseModelSchemas(schemas openapi3.Schemas) Models {
	models := make(Models)
	for modelName, schemaRef := range schemas {
		//if modelName != "microsoft.graph.application" {
		//	continue
		//}

		name := cleanName(modelName)
		if schema := parseSchemaRef(schemaRef); schema != nil {
			var f flattenedSchema
			f, _ = flattenSchema(schema, nil)
			models = parseSchemas(f, name, models)
		}
	}

	return models
}

type flattenedSchema struct {
	schemas openapi3.Schemas
	title   string
}

func flattenSchema(schema *openapi3.Schema, seenRefs []string) (flattenedSchema, []string) {
	if seenRefs == nil {
		seenRefs = make([]string, 0)
	}
	schemas := make(openapi3.Schemas, 0)
	title := ""
	if r := schema.Items; r != nil {
		if r.Ref != "" {
			for _, s := range seenRefs {
				if s == r.Ref {
					continue
				}
			}
			seenRefs = append(seenRefs, r.Ref)
		}
		if s := parseSchemaRef(r); s != nil {
			var result flattenedSchema
			result, seenRefs = flattenSchema(s, seenRefs)
			if result.title != "" {
				title = result.title
			}
			for k, v := range result.schemas {
				schemas[k] = v
			}
		}
	} else {
		if schema.AllOf != nil {
			for _, r := range schema.AllOf {
				if r.Ref != "" {
					for _, s := range seenRefs {
						if s == r.Ref {
							continue
						}
					}
					seenRefs = append(seenRefs, r.Ref)
				}
				if s := parseSchemaRef(r); s != nil {
					var result flattenedSchema
					result, seenRefs = flattenSchema(s, seenRefs)
					if result.title != "" {
						title = result.title
					}
					for k, v := range result.schemas {
						schemas[k] = v
					}
				}
			}
		}
		if schema.AnyOf != nil {
			for _, r := range schema.AnyOf {
				if r.Ref != "" {
					for _, s := range seenRefs {
						if s == r.Ref {
							continue
						}
					}
					seenRefs = append(seenRefs, r.Ref)
				}
				if s := parseSchemaRef(r); s != nil {
					var result flattenedSchema
					result, seenRefs = flattenSchema(s, seenRefs)
					if result.title != "" {
						title = result.title
					}
					for k, v := range result.schemas {
						schemas[k] = v
					}
				}
			}
		}
	}
	if schema.Title != "" {
		title = schema.Title
	}
	if schema.Properties != nil {
		for k, v := range schema.Properties {
			schemas[k] = v
		}
	}
	if len(schemas) == 0 {
		schemas = nil
	}
	return flattenedSchema{
		schemas: schemas,
		title:   title,
	}, seenRefs
}

func parseSchemaRef(schemaRef *openapi3.SchemaRef) *openapi3.Schema {
	if schemaRef.Value != nil {
		return schemaRef.Value
	}
	return nil
}

func parseSchemas(input flattenedSchema, modelName string, models Models) Models {
	if _, ok := models[modelName]; ok {
		return models
	}
	model := Model{
		Fields: make(map[string]*ModelField),
	}
	models[modelName] = &model
	for k, v := range input.schemas {
		schema := parseSchemaRef(v)
		result, _ := flattenSchema(schema, nil)
		title := ""
		if result.title != "" {
			title = strings.Title(result.title)
		} else {
			//title = fmt.Sprintf("%s%s", strings.Title(modelName), strings.Title(k))
			title = strings.Title(k)
		}
		field := ModelField{
			Title:       title,
			Description: schema.Description,
			Default:     schema.Default,
			Enum:        schema.Enum,
			JsonField:   k,
		}
		if result.schemas != nil {
			if _, ok := models[title]; !ok {
				models = parseSchemas(result, title, models)
			}
			field.ModelName = title
		}
		switch schema.Type {
		case "object":
			field.Type = FieldTypeModel
		case "array":
			field.Type = FieldTypeArray
		case "boolean":
			field.Type = FieldTypeBool
		case "integer":
			switch strings.ToLower(schema.Format) {
			case "int64":
				field.Type = FieldTypeInteger
			case "uint64":
				field.Type = FieldTypeIntegerUnsigned
			case "int32":
				field.Type = FieldTypeInteger32
			case "uint32":
				field.Type = FieldTypeIntegerUnsigned32
			case "int16":
				field.Type = FieldTypeInteger16
			case "uint16":
				field.Type = FieldTypeIntegerUnsigned16
			case "int8":
				field.Type = FieldTypeInteger8
			case "uint8":
				field.Type = FieldTypeIntegerUnsigned8
			default:
				field.Type = FieldTypeInteger
			}
		case "string":
			switch strings.ToLower(schema.Format) {
			case "base64url":
				field.Type = FieldTypeBase64
			case "date":
				field.Type = FieldTypeDate
			case "date-time":
				field.Type = FieldTypeDateTime
			case "duration":
				field.Type = FieldTypeDuration
			case "time":
				field.Type = FieldTypeTime
			case "uuid":
				field.Type = FieldTypeUuid
			case "":
				field.Type = FieldTypeString
			default:
				field.Type = FieldTypeString
			}
		default:
			if field.ModelName == "" {
				field.Type = FieldTypeInterface
			} else {
				field.Type = FieldTypeModel
			}
		}
		model.Fields[cleanName(k)] = &field
	}
	return models
}
