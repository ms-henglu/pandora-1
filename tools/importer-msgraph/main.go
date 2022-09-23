package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

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

func normalizeFieldName(segment string) (field string) {
	if segment[0] == '{' {
		field = segment[1 : len(segment)-1]
		field = strings.Title(field)
		field = regexp.MustCompile("([^A-Za-z0-9])").ReplaceAllString(field, "")
	}
	return
}

func NewResourceId(path string, tag string) (id ResourceId) {
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
				} else if strings.HasSuffix(strings.ToLower(tag), ".actions") {
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

type Endpoint struct {
	id        ResourceId
	path      string
	pathItem  *openapi3.PathItem
	method    string
	operation *openapi3.Operation
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

	endpointsByTag := parseEndpoints(spec.Paths)

	// smaller map for easier inspection
	applications := make(map[string][]*Endpoint)
	for tag, endpoint := range endpointsByTag {
		if strings.Contains(tag, "application") {
			applications[tag] = endpoint
		}
	}

	fmt.Println("breakpoint here")

	//models := make(map[string]*openapi3.SchemaRef)
	//ml := []string{
	//	"application", "directoryObject", "group", "user", "servicePrincipal",
	//}
	//for _, m := range ml {
	//	models[m] = spec.Components.Schemas[fmt.Sprintf("microsoft.graph.%s", m)]
	//}
	//
	//// models
	//for otype, schema := range spec.Components.Schemas {
	//	fmt.Printf("%s: %#v\n", otype, schema)
	//}

	//models := parseModels(spec.Components.Schemas)
	//fmt.Printf("%T", models)

	models := parseModelSchemas(spec.Components.Schemas)
	fmt.Printf("%T", models)

	tmpl := make([]string, 0)
	for name, model := range models {
		fields := make([]string, 0)
		for n, f := range model.Fields {
			if n[:1] == "@" {
				continue
			}
			fields = append(fields, fmt.Sprintf(`	%s %s`, n, f.Type))
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
	tmpls := fmt.Sprintf("package main\n\n%s", strings.Join(tmpl, "\n\n"))
	err := os.WriteFile("/Users/tom/git/hashicorp/pandora/tools/importer-msgraph/models.go", []byte(tmpls), 0644)
	if err != nil {
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

func parseEndpoints(paths openapi3.Paths) (ret map[string][]*Endpoint) {
	ret = make(map[string][]*Endpoint)
	for path, item := range paths {
		for method, operation := range item.Operations() {
			if operation.Tags == nil {
				continue
			}
			for _, tag := range operation.Tags {
				endpoint := Endpoint{
					id:        NewResourceId(path, tag),
					path:      path,
					pathItem:  item,
					method:    method,
					operation: operation,
				}
				ret[tag] = append(ret[tag], &endpoint)
			}
		}
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
	Type        FieldType
	Description string
	Default     interface{}
	Enum        []interface{}
	ModelName   string
}

type FieldType uint

func (t FieldType) String() string {
	switch t {
	case FieldTypeModel, FieldTypeInterface:
		return "interface{}"
	case FieldTypeString:
		return "string"
	case FieldTypeInt:
		return "int"
	case FieldTypeBool:
		return "bool"
	}
	return ""
}

const (
	FieldTypeModel FieldType = iota
	FieldTypeString
	FieldTypeInt
	FieldTypeBool
	FieldTypeInterface
)

func parseModelSchemas(schemas openapi3.Schemas) Models {
	models := make(Models)
	for modelName, schemaRef := range schemas {
		//if modelName != "microsoft.graph.application" {
		//	continue
		//}

		name := regexp.MustCompile("[^a-zA-Z0-9]").ReplaceAllString(strings.Title(strings.TrimPrefix(modelName, "microsoft.graph.")), "")
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
		field := ModelField{
			Description: schema.Description,
			Default:     schema.Default,
			Enum:        schema.Enum,
		}
		if result.schemas != nil {
			extraModelName := ""
			if result.title != "" {
				extraModelName = strings.Title(result.title)
			} else {
				extraModelName = fmt.Sprintf("%s%s", strings.Title(modelName), strings.Title(k))
			}
			if _, ok := models[extraModelName]; !ok {
				models = parseSchemas(result, extraModelName, models)
			}
			field.Type = FieldTypeModel
			field.ModelName = extraModelName
		} else {
			switch schema.Type {
			case "string":
				field.Type = FieldTypeString
			default:
				field.Type = FieldTypeInterface
			}
		}
		model.Fields[k] = &field
	}
	return models
}
